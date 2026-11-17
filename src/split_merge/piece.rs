use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use thiserror::Error;

use crate::util;

/// Magic bytes identifying a Transformer split piece (`TFSP`).
pub const PIECE_MAGIC: &[u8; 4] = b"TFSP";
/// Current binary piece header format version.
pub const PIECE_FORMAT_VERSION: u8 = 1;
/// Maximum permitted embedded filename length in bytes.
pub const MAX_FILENAME_LEN: usize = 4096;

/// Byte offset of the 32-byte per-piece BLAKE3 hash within a serialized header:
/// magic (4) + version (1) + tool_version (3) + split_id (16)
/// + piece_index (8) + total_pieces (8) + original_file_size (8) + original_file_hash (32) = 80.
pub const PIECE_HASH_OFFSET: u64 = 80;
/// Length of the fixed portion of the piece header before the variable filename bytes.
pub const FIXED_HEADER_LEN: u64 = 114;

const TOOL_VERSION_MAJOR: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_MAJOR"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};
const TOOL_VERSION_MINOR: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_MINOR"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};
const TOOL_VERSION_PATCH: u8 = match u8::from_str_radix(env!("CARGO_PKG_VERSION_PATCH"), 10) {
    Ok(v) => v,
    Err(_) => 0,
};

/// Tool semantic version embedded in piece headers.
pub const CURRENT_TOOL_VERSION: [u8; 3] = [
    TOOL_VERSION_MAJOR,
    TOOL_VERSION_MINOR,
    TOOL_VERSION_PATCH,
];

/// Errors produced when reading, validating, splitting, or merging piece files.
#[derive(Error, Debug)]
pub enum PieceError {
    #[error("Invalid magic bytes: not a Transformer split piece")]
    InvalidMagic,

    #[error("Unsupported piece format version {0} (supported: {PIECE_FORMAT_VERSION})")]
    UnsupportedVersion(u8),

    #[error("Invalid piece header: {0}")]
    InvalidHeader(String),

    #[error("Missing piece(s) for '{filename}': missing indices {missing:?}")]
    MissingPieces { filename: String, missing: Vec<u64> },

    #[error("Duplicate piece index {0} found")]
    DuplicatePiece(u64),

    #[error("Metadata mismatch on piece {piece_index}: {reason}")]
    MetadataMismatch { piece_index: u64, reason: String },

    #[error("Piece {piece_index} ({}) is corrupted (BLAKE3 checksum mismatch)", path.display())]
    PieceCorrupted { piece_index: u64, path: PathBuf },

    #[error("Merged file size mismatch: expected {expected} bytes, got {actual} bytes")]
    FileSizeMismatch { expected: u64, actual: u64 },

    #[error("Merged file BLAKE3 checksum mismatch: expected {expected}, got {actual}")]
    FileHashMismatch { expected: String, actual: String },

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Self-describing metadata header stored at the beginning of every split piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceHeader {
    pub format_version: u8,
    pub tool_version: [u8; 3],
    pub split_id: [u8; 16],
    pub piece_index: u64,
    pub total_pieces: u64,
    pub original_file_size: u64,
    pub original_file_hash: [u8; 32],
    pub piece_hash: [u8; 32],
    pub original_filename: String,
}

impl PieceHeader {
    /// Returns the serialized header byte length for a given sanitized filename.
    pub fn header_len_for(filename: &str) -> u64 {
        FIXED_HEADER_LEN + filename.len() as u64
    }

    /// Total serialized byte length of this header (including the filename bytes).
    pub fn header_len(&self) -> u64 {
        Self::header_len_for(&self.original_filename)
    }

    /// Writes the serialized header to `writer`.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), PieceError> {
        let name_bytes = self.original_filename.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_FILENAME_LEN {
            return Err(PieceError::InvalidHeader(format!(
                "Filename length {} out of bounds (1..={MAX_FILENAME_LEN})",
                name_bytes.len()
            )));
        }
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
            PieceError::InvalidHeader("Filename exceeds maximum u16 length".to_string())
        })?;

        writer.write_all(PIECE_MAGIC)?;
        writer.write_all(&[self.format_version])?;
        writer.write_all(&self.tool_version)?;
        writer.write_all(&self.split_id)?;
        writer.write_all(&self.piece_index.to_le_bytes())?;
        writer.write_all(&self.total_pieces.to_le_bytes())?;
        writer.write_all(&self.original_file_size.to_le_bytes())?;
        writer.write_all(&self.original_file_hash)?;
        writer.write_all(&self.piece_hash)?;
        writer.write_all(&name_len.to_le_bytes())?;
        writer.write_all(name_bytes)?;
        Ok(())
    }

    /// Reads and validates a piece header from `reader`.
    pub fn read_from(reader: &mut impl Read) -> Result<Self, PieceError> {
        let mut magic = [0u8; 4];
        match reader.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(PieceError::InvalidMagic);
            }
            Err(e) => return Err(PieceError::Io(e)),
        }
        if &magic != PIECE_MAGIC {
            return Err(PieceError::InvalidMagic);
        }

        let mut ver_buf = [0u8; 1];
        reader.read_exact(&mut ver_buf)?;
        let format_version = ver_buf[0];
        if format_version != PIECE_FORMAT_VERSION {
            return Err(PieceError::UnsupportedVersion(format_version));
        }

        let mut tool_version = [0u8; 3];
        reader.read_exact(&mut tool_version)?;

        let mut split_id = [0u8; 16];
        reader.read_exact(&mut split_id)?;

        let piece_index = read_u64_le(reader)?;
        let total_pieces = read_u64_le(reader)?;
        let original_file_size = read_u64_le(reader)?;

        if total_pieces == 0 {
            return Err(PieceError::InvalidHeader(
                "total_pieces cannot be zero".to_string(),
            ));
        }
        if piece_index >= total_pieces {
            return Err(PieceError::InvalidHeader(format!(
                "piece_index ({piece_index}) must be less than total_pieces ({total_pieces})"
            )));
        }

        let mut original_file_hash = [0u8; 32];
        reader.read_exact(&mut original_file_hash)?;

        let mut piece_hash = [0u8; 32];
        reader.read_exact(&mut piece_hash)?;

        let mut name_len_buf = [0u8; 2];
        reader.read_exact(&mut name_len_buf)?;
        let name_len = u16::from_le_bytes(name_len_buf) as usize;
        if name_len == 0 || name_len > MAX_FILENAME_LEN {
            return Err(PieceError::InvalidHeader(format!(
                "Invalid filename length ({name_len} bytes)"
            )));
        }

        let mut name_bytes = vec![0u8; name_len];
        reader.read_exact(&mut name_bytes)?;
        let raw_name = String::from_utf8(name_bytes).map_err(|e| {
            PieceError::InvalidHeader(format!("Embedded filename is not valid UTF-8: {e}"))
        })?;
        let original_filename = util::sanitize_filename(&raw_name).ok_or_else(|| {
            PieceError::InvalidHeader("Unsafe or empty filename in piece header".to_string())
        })?;

        Ok(Self {
            format_version,
            tool_version,
            split_id,
            piece_index,
            total_pieces,
            original_file_size,
            original_file_hash,
            piece_hash,
            original_filename,
        })
    }
}

/// Inspects a piece file on disk and returns its parsed [`PieceHeader`].
pub fn inspect_piece(path: &Path) -> Result<PieceHeader, PieceError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    PieceHeader::read_from(&mut reader)
}

/// Formats a byte slice as a lowercase hexadecimal string.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn read_u64_le(reader: &mut impl Read) -> Result<u64, PieceError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_piece_header_roundtrip() {
        let header = PieceHeader {
            format_version: PIECE_FORMAT_VERSION,
            tool_version: CURRENT_TOOL_VERSION,
            split_id: [0xAB; 16],
            piece_index: 2,
            total_pieces: 5,
            original_file_size: 123_456_789,
            original_file_hash: [0x11; 32],
            piece_hash: [0x22; 32],
            original_filename: "archive.tar.zst".to_string(),
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf).expect("write_to failed");
        assert_eq!(buf.len() as u64, header.header_len());

        let decoded = PieceHeader::read_from(&mut Cursor::new(&buf)).expect("read_from failed");
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_piece_header_sanitizes_traversal_filename() {
        let header = PieceHeader {
            format_version: PIECE_FORMAT_VERSION,
            tool_version: CURRENT_TOOL_VERSION,
            split_id: [0xCD; 16],
            piece_index: 0,
            total_pieces: 1,
            original_file_size: 10,
            original_file_hash: [0x33; 32],
            piece_hash: [0x44; 32],
            original_filename: "../../../../etc/passwd".to_string(),
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();

        let decoded = PieceHeader::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded.original_filename, "passwd");
    }

    #[test]
    fn test_piece_header_rejects_invalid_magic_and_version() {
        let err = PieceHeader::read_from(&mut Cursor::new(b"NOPE")).unwrap_err();
        assert!(matches!(err, PieceError::InvalidMagic));

        let mut bad_ver = Vec::from(*PIECE_MAGIC);
        bad_ver.push(99);
        let err = PieceHeader::read_from(&mut Cursor::new(&bad_ver)).unwrap_err();
        assert!(matches!(err, PieceError::UnsupportedVersion(99)));
    }
}
