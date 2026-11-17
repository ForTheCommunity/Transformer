use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{
    split_merge::piece::{PieceError, PieceHeader, bytes_to_hex},
    util::{TempFileGuard, random_hex_id},
};

const IO_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Progress updates emitted while merging split pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeProgress {
    /// Reading, verifying, and writing payload bytes for `piece_index`.
    Merging {
        piece_index: u64,
        total_pieces: u64,
        bytes_written: u64,
        total_bytes: u64,
    },
}

/// Summary returned upon a successful, BLAKE3-verified merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeResult {
    pub output_path: PathBuf,
    pub split_id: [u8; 16],
    pub original_filename: String,
    pub total_bytes: u64,
    pub total_pieces: u64,
    pub file_hash: [u8; 32],
}

enum MergeTarget<'a> {
    Directory(&'a Path),
    File(&'a Path),
}

/// Merges all pieces belonging to the same split group as `seed_piece` into `output_dir`,
/// restoring the sanitized original filename embedded in the piece headers and verifying
/// per-piece and full-file BLAKE3 checksums.
pub fn merge_pieces<F>(
    seed_piece: &Path,
    output_dir: &Path,
    on_progress: F,
) -> Result<MergeResult>
where
    F: FnMut(MergeProgress),
{
    merge_pieces_impl(seed_piece, MergeTarget::Directory(output_dir), on_progress)
}

/// Merges all pieces belonging to the same split group as `seed_piece` directly to `output_file`,
/// verifying per-piece and full-file BLAKE3 checksums.
pub fn merge_pieces_to_file<F>(
    seed_piece: &Path,
    output_file: &Path,
    on_progress: F,
) -> Result<MergeResult>
where
    F: FnMut(MergeProgress),
{
    merge_pieces_impl(seed_piece, MergeTarget::File(output_file), on_progress)
}

fn merge_pieces_impl<F>(
    seed_piece: &Path,
    target: MergeTarget<'_>,
    mut on_progress: F,
) -> Result<MergeResult>
where
    F: FnMut(MergeProgress),
{
    // Read and validate the seed piece header
    let seed_header = {
        let file = File::open(seed_piece)?;
        let mut reader = BufReader::new(file);
        PieceHeader::read_from(&mut reader)?
    };

    // Scan the seed piece's parent directory for matching split_id pieces
    let pieces_dir = seed_piece
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut discovered: BTreeMap<u64, (PathBuf, PieceHeader)> = BTreeMap::new();

    for entry in fs::read_dir(pieces_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let header = {
            let file = File::open(&path)?;
            let mut reader = BufReader::new(file);
            match PieceHeader::read_from(&mut reader) {
                Ok(h) => h,
                Err(PieceError::InvalidMagic | PieceError::UnsupportedVersion(_)) => continue,
                Err(e) => {
                    // Propagate if this is the seed itself (already checked), otherwise skip unrelated corrupt non-matching files
                    if path == seed_piece {
                        return Err(e.into());
                    }
                    continue;
                }
            }
        };

        if header.split_id != seed_header.split_id {
            continue;
        }

        validate_piece_consistency(&seed_header, &header)?;

        if discovered.contains_key(&header.piece_index) {
            return Err(PieceError::DuplicatePiece(header.piece_index).into());
        }
        discovered.insert(header.piece_index, (path, header));
    }

    // Verify all piece indices 0..total_pieces are present before writing output
    let missing: Vec<u64> = (0..seed_header.total_pieces)
        .filter(|idx| !discovered.contains_key(idx))
        .collect();
    if !missing.is_empty() {
        return Err(PieceError::MissingPieces {
            filename: seed_header.original_filename,
            missing,
        }
        .into());
    }

    // Pre-check total payload size matches expected original_file_size
    let mut expected_payload_sum = 0u64;
    for (path, header) in discovered.values() {
        let file_len = fs::metadata(path)?.len();
        if file_len < header.header_len() {
            return Err(PieceError::PieceCorrupted {
                piece_index: header.piece_index,
                path: path.clone(),
            }
            .into());
        }
        expected_payload_sum += file_len - header.header_len();
    }
    if expected_payload_sum != seed_header.original_file_size {
        return Err(PieceError::FileSizeMismatch {
            expected: seed_header.original_file_size,
            actual: expected_payload_sum,
        }
        .into());
    }

    // Resolve destination path and create atomic temporary file
    let dest_path = match target {
        MergeTarget::Directory(dir) => {
            if dir.exists() && !dir.is_dir() {
                return Err(anyhow::anyhow!("Output path exists and is not a directory"));
            }
            fs::create_dir_all(dir)?;
            dir.join(&seed_header.original_filename)
        }
        MergeTarget::File(file_path) => {
            if let Some(parent) = file_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            file_path.to_path_buf()
        }
    };

    let tmp_dir = dest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp_path = tmp_dir.join(format!("{}.merge.tmp", random_hex_id()));
    let mut guard = TempFileGuard::new(tmp_path);

    // Stream, hash-verify each piece, and compute overall BLAKE3 digest
    let mut full_hasher = blake3::Hasher::new();
    let mut total_bytes_written = 0u64;
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];

    {
        let out_file = File::create(guard.path())?;
        let mut writer = BufWriter::new(out_file);

        for (piece_index, (piece_path, piece_header)) in &discovered {
            let mut piece_file = File::open(piece_path)?;
            piece_file.seek(SeekFrom::Start(piece_header.header_len()))?;
            let mut reader = BufReader::new(piece_file);
            let mut piece_hasher = blake3::Hasher::new();

            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                let chunk = &buffer[..n];
                piece_hasher.update(chunk);
                full_hasher.update(chunk);
                writer.write_all(chunk)?;

                total_bytes_written += n as u64;
                on_progress(MergeProgress::Merging {
                    piece_index: *piece_index,
                    total_pieces: seed_header.total_pieces,
                    bytes_written: n as u64,
                    total_bytes: seed_header.original_file_size,
                });
            }

            let actual_piece_hash = *piece_hasher.finalize().as_bytes();
            if actual_piece_hash != piece_header.piece_hash {
                return Err(PieceError::PieceCorrupted {
                    piece_index: *piece_index,
                    path: piece_path.clone(),
                }
                .into());
            }
        }

        writer.flush()?;
    }

    if total_bytes_written != seed_header.original_file_size {
        return Err(PieceError::FileSizeMismatch {
            expected: seed_header.original_file_size,
            actual: total_bytes_written,
        }
        .into());
    }

    let actual_file_hash = *full_hasher.finalize().as_bytes();
    if actual_file_hash != seed_header.original_file_hash {
        return Err(PieceError::FileHashMismatch {
            expected: bytes_to_hex(&seed_header.original_file_hash),
            actual: bytes_to_hex(&actual_file_hash),
        }
        .into());
    }

    fs::rename(guard.path(), &dest_path)?;
    guard.disarm();

    Ok(MergeResult {
        output_path: dest_path,
        split_id: seed_header.split_id,
        original_filename: seed_header.original_filename,
        total_bytes: total_bytes_written,
        total_pieces: seed_header.total_pieces,
        file_hash: actual_file_hash,
    })
}

fn validate_piece_consistency(seed: &PieceHeader, candidate: &PieceHeader) -> Result<(), PieceError> {
    if candidate.total_pieces != seed.total_pieces {
        return Err(PieceError::MetadataMismatch {
            piece_index: candidate.piece_index,
            reason: format!(
                "total_pieces mismatch (expected {}, found {})",
                seed.total_pieces, candidate.total_pieces
            ),
        });
    }
    if candidate.original_file_size != seed.original_file_size {
        return Err(PieceError::MetadataMismatch {
            piece_index: candidate.piece_index,
            reason: format!(
                "original_file_size mismatch (expected {}, found {})",
                seed.original_file_size, candidate.original_file_size
            ),
        });
    }
    if candidate.original_file_hash != seed.original_file_hash {
        return Err(PieceError::MetadataMismatch {
            piece_index: candidate.piece_index,
            reason: "original_file_hash mismatch".to_string(),
        });
    }
    if candidate.original_filename != seed.original_filename {
        return Err(PieceError::MetadataMismatch {
            piece_index: candidate.piece_index,
            reason: format!(
                "original_filename mismatch (expected '{}', found '{}')",
                seed.original_filename, candidate.original_filename
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_merge::split::split_file;

    #[test]
    fn test_split_and_merge_roundtrip_with_renamed_pieces_and_noise() {
        let temp_dir = std::env::temp_dir().join(format!("tf_merge_test_{}", random_hex_id()));
        let pieces_dir = temp_dir.join("pieces");
        let out_dir = temp_dir.join("merged");
        fs::create_dir_all(&temp_dir).unwrap();

        // Filename intentionally contains `_piece_` to verify header-based restoration
        let src_path = temp_dir.join("my_piece_archive.bin");
        let payload: Vec<u8> = (0u8..=255).cycle().take(15_000).collect();
        fs::write(&src_path, &payload).unwrap();

        let split_res = split_file(&src_path, 4096, &pieces_dir, |_| {}).expect("split failed");
        assert_eq!(split_res.total_pieces, 4);

        // Add unrelated noise files & a directory in pieces_dir
        fs::write(pieces_dir.join("my_piece_archive.bin"), b"unrelated decoy file").unwrap();
        fs::write(pieces_dir.join("notes.txt"), b"random text").unwrap();
        fs::create_dir_all(pieces_dir.join("my_piece_archive.bin_dir")).unwrap();

        // Rename pieces to completely anonymous names to prove filename independence
        let mut renamed_pieces = Vec::new();
        for (i, p) in split_res.piece_paths.iter().enumerate() {
            let new_path = pieces_dir.join(format!("anon_{}_{}.dat", random_hex_id(), i));
            fs::rename(p, &new_path).unwrap();
            renamed_pieces.push(new_path);
        }

        // Also put a second independent split in the SAME directory
        let other_src = temp_dir.join("my_piece_archive.bin");
        fs::write(&other_src, b"different contents of same length or size!").unwrap();
        let _other_split = split_file(&other_src, 150, &pieces_dir, |_| {}).unwrap();

        // Merge using piece 2 as seed
        let mut merged_bytes = 0u64;
        let merge_res = merge_pieces(&renamed_pieces[2], &out_dir, |p| match p {
            MergeProgress::Merging { bytes_written, .. } => merged_bytes += bytes_written,
        })
        .expect("merge failed");

        assert_eq!(merge_res.original_filename, "my_piece_archive.bin");
        assert_eq!(merge_res.output_path, out_dir.join("my_piece_archive.bin"));
        assert_eq!(merge_res.total_bytes, 15_000);
        assert_eq!(merged_bytes, 15_000);
        assert_eq!(fs::read(&merge_res.output_path).unwrap(), payload);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_merge_rejects_missing_piece() {
        let temp_dir = std::env::temp_dir().join(format!("tf_merge_miss_{}", random_hex_id()));
        let pieces_dir = temp_dir.join("pieces");
        let out_dir = temp_dir.join("merged");
        fs::create_dir_all(&temp_dir).unwrap();

        let src_path = temp_dir.join("data.bin");
        fs::write(&src_path, vec![7u8; 1000]).unwrap();

        let split_res = split_file(&src_path, 300, &pieces_dir, |_| {}).unwrap();
        // Delete piece 1
        fs::remove_file(&split_res.piece_paths[1]).unwrap();

        let err = merge_pieces(&split_res.piece_paths[0], &out_dir, |_| {}).unwrap_err();
        let piece_err = err.downcast_ref::<PieceError>().expect("expected PieceError");
        match piece_err {
            PieceError::MissingPieces { missing, .. } => assert_eq!(missing, &[1]),
            other => panic!("Expected MissingPieces, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_merge_rejects_corrupted_piece_and_cleans_temp() {
        let temp_dir = std::env::temp_dir().join(format!("tf_merge_corrupt_{}", random_hex_id()));
        let pieces_dir = temp_dir.join("pieces");
        let out_dir = temp_dir.join("merged");
        fs::create_dir_all(&temp_dir).unwrap();

        let src_path = temp_dir.join("secret.bin");
        fs::write(&src_path, vec![42u8; 1200]).unwrap();

        let split_res = split_file(&src_path, 400, &pieces_dir, |_| {}).unwrap();

        // Flip a byte in the payload of piece 2
        let mut piece2_bytes = fs::read(&split_res.piece_paths[2]).unwrap();
        let last = piece2_bytes.len() - 1;
        piece2_bytes[last] ^= 0xFF;
        fs::write(&split_res.piece_paths[2], &piece2_bytes).unwrap();

        let err = merge_pieces(&split_res.piece_paths[0], &out_dir, |_| {}).unwrap_err();
        let piece_err = err.downcast_ref::<PieceError>().expect("expected PieceError");
        assert!(matches!(
            piece_err,
            PieceError::PieceCorrupted { piece_index: 2, .. }
        ));

        // Verify no destination or leftover .merge.tmp file remains in out_dir
        assert!(!out_dir.join("secret.bin").exists());
        let leftovers: Vec<_> = fs::read_dir(&out_dir).unwrap().collect();
        assert!(leftovers.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
