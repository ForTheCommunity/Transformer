use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};

use crate::split_merge::piece::{
    CURRENT_TOOL_VERSION, PIECE_FORMAT_VERSION, PIECE_HASH_OFFSET, PieceHeader,
};

const IO_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Progress updates emitted while splitting a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitProgress {
    /// Computing the BLAKE3 hash of the original file.
    Hashing { bytes_read: u64, total_bytes: u64 },
    /// Writing split pieces and hashing each piece's payload.
    Splitting {
        piece_index: u64,
        total_pieces: u64,
        bytes_written: u64,
        total_bytes: u64,
    },
}

/// Summary returned upon a successful file split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    pub split_id: [u8; 16],
    pub original_filename: String,
    pub original_file_size: u64,
    pub original_file_hash: [u8; 32],
    pub total_pieces: u64,
    pub piece_paths: Vec<PathBuf>,
}

struct PiecesCleanupGuard {
    paths: Vec<PathBuf>,
    active: bool,
}

impl PiecesCleanupGuard {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            active: true,
        }
    }

    fn push(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for PiecesCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            for path in &self.paths {
                let _ = fs::remove_file(path);
            }
        }
    }
}

/// Computes `(header_len, payload_per_piece, total_pieces)` for a file of `file_size` bytes
/// and `original_filename`, where `piece_size` is the maximum total output piece file size
/// (`header + payload <= piece_size`).
pub fn calculate_split_layout(
    original_filename: &str,
    file_size: u64,
    piece_size: u64,
) -> Result<(u64, u64, u64)> {
    let header_len = PieceHeader::header_len_for(original_filename);
    if piece_size == 0 {
        return Err(anyhow!("Piece size cannot be zero"));
    }
    if file_size == 0 {
        return Err(anyhow!("Cannot split an empty (0-byte) file"));
    }
    if piece_size <= header_len {
        return Err(anyhow!(
            "Piece size ({piece_size} bytes) must be larger than the piece header size ({header_len} bytes)"
        ));
    }
    let payload_per_piece = piece_size - header_len;
    if payload_per_piece > file_size {
        return Err(anyhow!(
            "Piece payload capacity ({payload_per_piece} bytes) is greater than file size ({file_size} bytes)"
        ));
    }
    let total_pieces = file_size.div_ceil(payload_per_piece);
    Ok((header_len, payload_per_piece, total_pieces))
}

/// Splits `file_path` into self-describing pieces whose total on-disk size (header + payload)
/// is capped at `piece_size` bytes inside `output_dir`, embedding a BLAKE3-verified [`PieceHeader`]
/// into every piece.
pub fn split_file<F>(
    file_path: &Path,
    piece_size: u64,
    output_dir: &Path,
    mut on_progress: F,
) -> Result<SplitResult>
where
    F: FnMut(SplitProgress),
{
    let metadata = fs::metadata(file_path)?;
    if metadata.is_dir() {
        return Err(anyhow!("Expected a file path, not a directory"));
    }

    let original_filename = file_path
        .file_name()
        .and_then(|f_n| f_n.to_str())
        .ok_or_else(|| anyhow!("Invalid filename: unable to extract valid UTF-8 filename"))?
        .to_string();

    let file_size = metadata.len();
    let (_header_len, payload_per_piece, total_pieces) =
        calculate_split_layout(&original_filename, file_size, piece_size)?;

    if output_dir.exists() && !output_dir.is_dir() {
        return Err(anyhow!("Output path exists and is not a directory"));
    }
    fs::create_dir_all(output_dir)?;

    let width = total_pieces.to_string().len();

    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];

    // Compute whole-file BLAKE3 digest
    let original_file_hash = {
        let mut reader = BufReader::new(&mut file);
        let mut hasher = blake3::Hasher::new();
        let mut hashed_bytes = 0u64;

        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            hashed_bytes += n as u64;
            on_progress(SplitProgress::Hashing {
                bytes_read: n as u64,
                total_bytes: file_size,
            });
        }

        if hashed_bytes != file_size {
            return Err(anyhow!(
                "Source file size changed during hashing (expected {file_size}, read {hashed_bytes})"
            ));
        }

        *hasher.finalize().as_bytes()
    };

    // Rewind source file for splitting
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);

    let mut split_id = [0u8; 16];
    rand::fill(&mut split_id);

    let mut guard = PiecesCleanupGuard::new();
    let mut total_written = 0u64;

    // Stream pieces with headers and per-piece BLAKE3 checksums
    for piece_index in 0..total_pieces {
        let piece_name = format!(
            "{}_piece_{:0width$}",
            original_filename,
            piece_index,
            width = width
        );
        let piece_path = output_dir.join(piece_name);
        guard.push(piece_path.clone());

        let out_file = File::create(&piece_path)?;
        let mut writer = BufWriter::new(out_file);

        let mut header = PieceHeader {
            format_version: PIECE_FORMAT_VERSION,
            tool_version: CURRENT_TOOL_VERSION,
            split_id,
            piece_index,
            total_pieces,
            original_file_size: file_size,
            original_file_hash,
            piece_hash: [0u8; 32],
            original_filename: original_filename.clone(),
        };
        header.write_to(&mut writer)?;

        let mut piece_hasher = blake3::Hasher::new();
        let mut piece_written = 0u64;

        while piece_written < payload_per_piece {
            let remaining = (payload_per_piece - piece_written) as usize;
            let to_read = remaining.min(buffer.len());
            let n = reader.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }

            piece_hasher.update(&buffer[..n]);
            writer.write_all(&buffer[..n])?;
            piece_written += n as u64;
            total_written += n as u64;

            on_progress(SplitProgress::Splitting {
                piece_index,
                total_pieces,
                bytes_written: n as u64,
                total_bytes: file_size,
            });
        }

        if piece_written == 0 {
            return Err(anyhow!(
                "Source file ended prematurely at piece {piece_index} (file modified concurrently?)"
            ));
        }

        // Patch finalized BLAKE3 piece hash into the header
        header.piece_hash = *piece_hasher.finalize().as_bytes();
        writer.flush()?;
        writer.seek(SeekFrom::Start(PIECE_HASH_OFFSET))?;
        writer.write_all(&header.piece_hash)?;
        writer.flush()?;
    }

    if total_written != file_size {
        return Err(anyhow!(
            "Source file size changed during splitting (expected {file_size}, wrote {total_written})"
        ));
    }

    let piece_paths = guard.paths.clone();
    guard.disarm();

    Ok(SplitResult {
        split_id,
        original_filename,
        original_file_size: file_size,
        original_file_hash,
        total_pieces,
        piece_paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split_merge::piece::inspect_piece;
    use crate::util::random_hex_id;

    #[test]
    fn test_split_writes_valid_headers_and_blake3_hashes() {
        let temp_dir = std::env::temp_dir().join(format!("tf_split_test_{}", random_hex_id()));
        let out_dir = temp_dir.join("pieces");
        fs::create_dir_all(&temp_dir).unwrap();

        let src_path = temp_dir.join("sample_data.bin");
        let payload: Vec<u8> = (0u8..=255).cycle().take(10_500).collect();
        fs::write(&src_path, &payload).unwrap();

        let expected_file_hash = *blake3::hash(&payload).as_bytes();
        let mut hashing_bytes = 0u64;
        let mut splitting_bytes = 0u64;

        let result = split_file(&src_path, 4096, &out_dir, |p| match p {
            SplitProgress::Hashing { bytes_read, .. } => hashing_bytes += bytes_read,
            SplitProgress::Splitting { bytes_written, .. } => splitting_bytes += bytes_written,
        })
        .expect("split failed");

        assert_eq!(result.total_pieces, 3);
        assert_eq!(result.piece_paths.len(), 3);
        assert_eq!(result.original_file_size, 10_500);
        assert_eq!(result.original_file_hash, expected_file_hash);
        assert_eq!(hashing_bytes, 10_500);
        assert_eq!(splitting_bytes, 10_500);

        let expected_header_len = PieceHeader::header_len_for("sample_data.bin");
        let payload_cap = (4096 - expected_header_len) as usize;

        // Verify each piece's on-disk cap, header, and payload hash
        let expected_slices: [&[u8]; 3] = [
            &payload[0..payload_cap],
            &payload[payload_cap..payload_cap * 2],
            &payload[payload_cap * 2..],
        ];
        for (idx, piece_path) in result.piece_paths.iter().enumerate() {
            let on_disk_len = fs::metadata(piece_path).unwrap().len();
            assert!(on_disk_len <= 4096);
            if idx < 2 {
                assert_eq!(on_disk_len, 4096);
            }

            let hdr = inspect_piece(piece_path).expect("inspect_piece failed");
            assert_eq!(hdr.split_id, result.split_id);
            assert_eq!(hdr.piece_index, idx as u64);
            assert_eq!(hdr.total_pieces, 3);
            assert_eq!(hdr.original_filename, "sample_data.bin");
            assert_eq!(hdr.original_file_hash, expected_file_hash);

            let raw = fs::read(piece_path).unwrap();
            let piece_payload = &raw[hdr.header_len() as usize..];
            assert_eq!(piece_payload, expected_slices[idx]);
            assert_eq!(hdr.piece_hash, *blake3::hash(piece_payload).as_bytes());
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_split_validation_errors() {
        let temp_dir = std::env::temp_dir().join(format!("tf_split_err_{}", random_hex_id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let src_path = temp_dir.join("tiny.txt");
        fs::write(&src_path, b"hello").unwrap();

        assert!(split_file(&src_path, 0, &temp_dir, |_| {}).is_err());
        // Smaller than header size
        assert!(split_file(&src_path, 50, &temp_dir, |_| {}).is_err());
        // Equal to header size (0 payload capacity)
        let hdr_len = PieceHeader::header_len_for("tiny.txt");
        assert!(split_file(&src_path, hdr_len, &temp_dir, |_| {}).is_err());
        // Payload capacity > file size
        assert!(split_file(&src_path, hdr_len + 100, &temp_dir, |_| {}).is_err());
        assert!(split_file(&temp_dir, 500, &temp_dir, |_| {}).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_split_caps_five_times_piece_size_into_six_pieces() {
        let temp_dir = std::env::temp_dir().join(format!("tf_split_cap_{}", random_hex_id()));
        let out_dir = temp_dir.join("pieces");
        fs::create_dir_all(&temp_dir).unwrap();

        let src_path = temp_dir.join("five_kb.bin");
        let payload = vec![0x5Au8; 5 * 1024];
        fs::write(&src_path, &payload).unwrap();

        let res = split_file(&src_path, 1024, &out_dir, |_| {}).expect("split failed");
        assert_eq!(res.total_pieces, 6);
        for (i, p) in res.piece_paths.iter().enumerate() {
            let size = fs::metadata(p).unwrap().len();
            assert!(size <= 1024);
            if i < 5 {
                assert_eq!(size, 1024);
            }
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
