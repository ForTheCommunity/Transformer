# Changelog

## [0.1.1] - 2026-11-21

### Added
- **Self-Describing Split & Merge (`TFSP`)**:
  - Binary header format (`TFSP`) embedded into every split piece containing group ID, piece index, total piece count, and original file metadata.
  - End-to-end cryptographic integrity verification powered by **BLAKE3** (per-piece payload checksums and whole-file reconstructed digest).
  - Directory-wide piece discovery by `split_id`—pieces can be reassembled even if renamed or mixed with other files.
  - Atomic merge writes using temporary file guards to prevent partial or corrupted file leftovers.
- **Robust Encryption Modes**:
  - **Password Mode (`encrypt-pass` / `decrypt-pass`)**: Self-contained file encryption using Argon2id key derivation and AES-256-GCM chunked streaming.
  - **Keystore Mode (`encrypt-ks` / `decrypt-ks`)**: Master keystore key derivation using envelope encryption (DEK/KEK architecture).
  - **Standardized `TFMR` File Headers**: 10-byte authenticated metadata headers with AAD protection.
  - **Memory Zeroization**: Automatic clearing of sensitive cryptographic keys and passwords in memory using RAII zeroize guards.
  - **Path Traversal Protection**: Embedded filenames are sanitized to safe leaf basenames upon extraction.
- **Human-Readable Sizing**:
  - Added `format_bytes()` to format byte sizes across `B`, `KB`, `MB`, `GB`, and `TB`.
  - Replaced raw byte counters in split/merge terminal output with formatted human-readable metrics.
- **Cross-Platform Releases**:
  - Added GitHub Actions workflow supporting 12 target architectures (Windows, macOS Intel/Apple Silicon, Linux GNU/MUSL for x86_64, ARM64, ARMv7, i686, and RISC-V 64).
  - Automated `SHA256_CHECKSUMS.txt` generation.

### Changed
- Converted core splitting, merging, and cryptographic engines into a reusable library (`transformer` crate).
- Improved CLI progress reporting with live progress bars and ETA via `indicatif`.

---

## [0.1.0] - 2026-04-23

### Added
- Initial release of `transformer`.
- Basic file splitting and merging CLI commands.
- Configurable piece size with unit parsing (`B`, `KB`, `MB`, `GB`, `TB`).
