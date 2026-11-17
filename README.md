# 🛠 Transformer

A command-line utility for transforming files from one form to another.

-> Join [Matrix Room](https://matrix.to/#/#transformer:matrix.org)


# ❖ File Splitting Demo :
![transformer file splitting](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_split.gif?raw=true)

# ❖ File Merging Demo :
![transformer file merging](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_merge.gif?raw=true)

## ❖ Key Features

* **Split Big Files into Smaller Pieces**:
  * Break large files (like videos, backups, or archives) into smaller parts that never go over the maximum size you choose (in Bytes, KB, MB, GB, or TB)—great for fitting under upload or email limits.
* **Combine Pieces Back Together Safely**:
  * Rebuild your original file in one step, even if the pieces were renamed or mixed into a folder with other unrelated files.
  * **Automatic Safety Checks**: Before rebuilding your file, Transformer checks that all pieces are present and undamaged—and tells you right away if a piece is missing or corrupted, instead of giving you a broken file.
* **Two Easy Ways to Lock (Encrypt) Your Files**:
  * **Password Mode**: Lock and unlock any file using just a password—no extra files required.
  * **Keystore Mode**: Create one private "master key" file protected by a single master password, then use it to lock and unlock many files effortlessly.
* **Built-In Privacy & Protection**:
  * **Hides Original File Names**: Encrypted files are saved with random names so no one can guess what's inside by looking at the filename. When you unlock the file, its original name is automatically restored.
  * **Protects Your Passwords**: Prompts you to type passwords privately so they aren't saved in your terminal history, and clears secret keys from memory as soon as the work is finished.
  * **Detects Tampering**: Immediately catches modified or damaged encrypted files instead of outputting broken data.
* **Fast & Smooth on Large Files**:
  * Shows live progress bars while working, lets you tune buffer speed for large files, and includes an option to automatically clean up source files after encrypting or decrypting.
* **Developer-Friendly**:
  * Built as a reusable library (lib crate) too, so other developers can easily add Transformer's splitting, merging, and encryption features into their own softwares.

## ❖ Download & Installation

### Download binaries from [Releases](https://gitlab.com/ForTheCommunity/transformer/-/releases)

[![Download for Windows](https://img.shields.io/badge/download-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/ForTheCommunity/Transformer/releases)
[![Download for Linux](https://img.shields.io/badge/download-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://gitlab.com/ForTheCommunity/Transformer/-/releases)

### Install using [AppMan](https://github.com/ivan-hc/AppMan) / [AM](https://github.com/ivan-hc/AM)
```bash
appman install transformer
```

## ❖ Usage

## ✦ Splitting a File
Use the `split` subcommand to break a file into self-describing, BLAKE3-verified pieces.

```bash
transformer split --file-path <PATH> --piece-size <SIZE> --output <DIRECTORY>
```

> **Note:** `--piece-size` sets the **maximum total on-disk size** per piece (`header + payload <= piece_size`). For example, splitting a 5 MB file with `-p 1MB` caps every piece at `1 MB` on disk and produces 6 pieces (5 full `1 MB` pieces plus 1 small remainder piece). `--piece-size` must be larger than the piece header size (`114 + filename_len` bytes).

**Example:**
```bash
transformer split -f large_video.mp4 -p 100MB -o ./fragments
```

## ✦ Merging Pieces
Use the `merge` subcommand to reconstruct and verify the original file from a directory of pieces.
> **Note:** All pieces must be in the same folder/directory. Pieces are matched by their embedded `TFSP` header and `split_id` (not by filename), verified per-piece and end-to-end with **BLAKE3**, and written atomically.

```bash
transformer merge --piece <Any Piece> --folder <FOLDER_PATH>
```

**Example:**
```bash
transformer merge -p ~/Downloads/pieces/large_video.mp4_piece_0 -f ~/Downloads/
```

## ✦ Supported Units

The `--piece-size` (`-p`) flag supports the following case-insensitive units:

| Unit | Description |
| :--- | :--- |
| `B`  | Bytes |
| `KB` | Kilobytes |
| `MB` | Megabytes |
| `GB` | Gigabytes |
| `TB` | Terabytes |

---




## ❖ Encrypting/Decrypting Files

### ❖ 1. En/De-crypting files with a Password

#### ✦ Encrypting a file with a password:
Use the `encrypt-pass` subcommand to encrypt a file with a password directly (self-contained encryption).

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of file to encrypt |
| `-o` | `--output` | Path where encrypted file will be saved |
| `-p` | `--password` | Pass password via argument |
| `-c` | `--chunk-size` | Set Buffer/Chunk Size in MB (1–100, default: 1) |
| `-h` | `--help` | View details about this subcommand |

**Examples:**
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/
```

**Provide password via argument:**
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/ -p secret_password
```

**Set Buffer/Chunk Size (MB):**
```bash
transformer encrypt-pass -f video.mp4 -o ./encrypted_files/ -c 100
```
> **Tip:** The default chunk size (buffer) is 1 MB. When encrypting large files, increase this value (up to 100 MB) for significantly faster performance.

> **Security Note:** For security reasons, avoid passing your password directly as a command-line argument, as it will be saved in your shell history. If you omit the argument, the tool will automatically display a secure password prompt.

---

#### ✦ Decrypting a file with a password:
Use the `decrypt-pass` subcommand to decrypt a password-encrypted file.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of file to decrypt |
| `-o` | `--output` | Path where decrypted file will be saved |
| `-p` | `--password` | Pass password via argument |
| `-h` | `--help` | View details about this subcommand |

**Examples:**
```bash
transformer decrypt-pass -f sd3gdvs6.encrypted -o ./decrypted_files/
```

**Provide password via argument:**
```bash
transformer decrypt-pass -f sd3gdvs6.encrypted -o ./decrypted_files/ -p secret_password
```

> **Security Note:** For security reasons, avoid passing your password directly as a command-line argument, as it will be saved in your shell history. If you omit the argument, the tool will automatically display a secure password prompt.

---

### ❖ 2. En/De-crypting files with a Keystore

Using a Keystore allows you to manage encryption keys centrally. You create a keystore file protected by a master password, and then use that keystore to encrypt and decrypt multiple files seamlessly.

#### ✦ Creating a Keystore:
Use the `create-keystore` subcommand to generate a new master keystore file.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-o` | `--file-path` | Output path for keystore file |
| `-h` | `--help` | View details about this subcommand |

**Example:**
```bash
transformer create-keystore -o ./keystore.json
```
> **Note:** You will be securely prompted to set a master password for the keystore.

---

#### ✦ Encrypting with a Keystore:
Use the `encrypt` subcommand to encrypt a file using an existing keystore.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of file to encrypt |
| `-k` | `--keystore` | Path to keystore file |
| `-o` | `--output` | Output path where encrypted file will be saved |
| `-c` | `--chunk-size` | Set Buffer/Chunk Size in MB (1–100, default: 1) |
| `-h` | `--help` | View details about this subcommand |

**Examples:**
```bash
transformer encrypt -f video.mp4 -k ./keystore.json -o ./encrypted_files/
```

**Set Buffer/Chunk Size (MB):**
```bash
transformer encrypt -f video.mp4 -k ./keystore.json -o ./encrypted_files/ -c 100
```
> **Tip:** The default chunk size is 1 MB. When encrypting large files, set it to maximum (100 MB) for faster execution.

---

#### ✦ Decrypting with a Keystore:
Use the `decrypt` subcommand to decrypt a file using your keystore.

| Option | Long form | Description |
|--------|-----------|-------------|
| `-f` | `--file` | Path of encrypted file |
| `-k` | `--keystore` | Path to keystore file |
| `-o` | `--output` | Output path where decrypted file will be saved |
| `[PASSWORD]` | *(Argument)* | Optional master password passed directly as an argument |
| `-h` | `--help` | View details about this subcommand |

**Examples:**
```bash
transformer decrypt -f sd3gdvs6.encrypted -k ./keystore.json -o ./decrypted_files/
```

**Provide password via argument:**
```bash
transformer decrypt -f sd3gdvs6.encrypted -k ./keystore.json -o ./decrypted_files/ secret_password
```

> **Security Note:** For security reasons, avoid passing your password directly as a command-line argument, as it will be saved in your shell history. If you omit the argument, the tool will automatically display a secure password prompt.



---

# ❖ Cryptography & Security Architecture

Transformer uses state-of-the-art cryptographic primitives to guarantee both data **confidentiality** and **integrity**. 

### 1. Key Derivation Function (KDF) — Argon2
* **Purpose**: Safely derives cryptographic keys from user-supplied passwords, protecting against brute-force and GPU-accelerated cracking attacks.
* **Mechanism**: When a password or keystore is processed, Transformer uses **Argon2** combined with a freshly generated, cryptographically secure **16-byte random salt** (`SaltString`) to compute a password hash. The resulting raw hash bytes are mapped into a 32-byte (256-bit) **Key Encryption Key (KEK)**.

### 2. Encryption Primitive — AES-256-GCM
* **Purpose**: Provides Authenticated Encryption with Associated Data (AEAD), ensuring that ciphertext cannot be read or tampered with without detection.
* **Mechanism**: All key wrapping and data streaming operations utilize **AES-256-GCM**. Every block/chunk includes a cryptographic authentication tag that validates data integrity upon decryption.

### 3. Key Hierarchy & Key Wrapping (KEK & DEK)
* **Keystore Mode**: 
  * A user password derives a KEK via Argon2, which unlocks (decrypts) a randomly generated 32-byte **Master Key** safely stored inside an encrypted JSON keystore (`KeyStore`: containing version, salt, nonce, and wrapped key).
  * For each file encrypted, a unique per-file **Data Encryption Key (DEK)** (32 bytes) is generated, encrypted (wrapped) using the Master Key, and stored in the file header.
* **Password Mode (Self-Contained)**: 
  * A password-derived KEK directly wraps a unique per-file **DEK**, which is stored alongside the salt and nonces directly within the file header.

### 4. Streaming, Chunk Nonces, and Anti-Replay Protection
* **Chunked Stream Processing**: Files are read, encrypted, and written in adjustable chunks (`chunk_size`, ranging from 1 MB up to 100 MB for maximum throughput).
* **Unique Nonce Derivation**: To prevent nonce reuse vulnerabilities in AES-GCM across large streams, Transformer generates a random 12-byte `base_nonce` for each file and derives a unique nonce per chunk (`chunk_nonce`). It combines bytes 0–3 of the base nonce with an 8-byte little-endian chunk counter XOR-ed into bytes 4–11.

### 5. Secure Filename Preservation & Memory Zeroization
* The original file name is embedded securely at the very beginning of the plaintext stream (`[filename_len (4 B LE)] ++ [filename bytes]`) before chunk encryption. During decryption, Transformer extracts and sanitizes the leaf filename to prevent path-traversal attacks.
* Sensitive key material (Master Keys, KEKs, DEKs, and passwords) is wiped from memory on drop using volatile zeroization.

### 6. Standardized File Header (10 Bytes, Authenticated via AAD)
Every encrypted file begins with a fixed 10-byte common header passed as AES-GCM Associated Authenticated Data (AAD) when wrapping the DEK (alongside the 16-byte salt in Password mode) to prevent tampering and mode mismatch errors:

| Field | Size | Description |
| :--- | :--- | :--- |
| **Magic Bytes** | 4 B | Fixed sequence `b"TFMR"` to identify Transformer-encrypted files. |
| **Format Version** | 1 B | File format version (currently `0x01`). |
| **Mode** | 1 B | Encryption mode: `0x01` (`Keystore`) or `0x02` (`Password`). |
| **Cipher Suite** | 1 B | Cryptographic suite: `0x01` (`AES-256-GCM`). |
| **Tool Version** | 3 B | Semantic version `[major, minor, patch]` of the tool used to encrypt. |

### 7. On-Disk Encrypted File Layout:
* i. Password-Based Encryption Layout (Self-Contained) :
  ```text
  ┌────────────────────────────────────────────────────────────┐
  │  Magic Bytes      ( 4 B, b"TFMR")                          │
  │  Format Version   ( 1 B, 0x01)                             │
  │  Mode             ( 1 B, 0x02 = Password)                  │
  │  Cipher Suite     ( 1 B, 0x01 = AES-256-GCM)               │
  │  Tool Version     ( 3 B, [major, minor, patch])            │
  ├────────────────────────────────────────────────────────────┤
  │  Salt             (16 B, Argon2 salt)                      │
  │  DEK nonce        (12 B)                                   │
  │  Wrapped-DEK len  ( 4 B, little-endian u32)                │
  │  Wrapped DEK      (variable length)                        │
  │  Base nonce       (12 B, per-file stream base nonce)       │
  ├────────────────────────────────────────────────────────────┤
  │  Chunk 0 len      ( 4 B, LE u32)                           │
  │  Chunk 0 data     (chunk_len B)  ← raw data + 16-byte tag  │
  │  …                                                         │
  │  Chunk N len      ( 4 B, LE u32)                           │
  │  Chunk N data     (chunk_len B)                            │
  ├────────────────────────────────────────────────────────────┤
  │  EOS sentinel     ( 4 B, all zero)                         │
  └────────────────────────────────────────────────────────────┘
  ```
* ii. Keystore-Based Encryption Layout :
  ```text
  ┌────────────────────────────────────────────────────────────┐
  │  Magic Bytes      ( 4 B, b"TFMR")                          │
  │  Format Version   ( 1 B, 0x01)                             │
  │  Mode             ( 1 B, 0x01 = Keystore)                  │
  │  Cipher Suite     ( 1 B, 0x01 = AES-256-GCM)               │
  │  Tool Version     ( 3 B, [major, minor, patch])            │
  ├────────────────────────────────────────────────────────────┤
  │  DEK nonce        (12 B)                                   │
  │  Wrapped-DEK len  ( 4 B, little-endian u32)                │
  │  Wrapped DEK      (variable length)                        │
  │  Base nonce       (12 B, per-file stream base nonce)       │
  ├────────────────────────────────────────────────────────────┤
  │  Chunk 0 len      ( 4 B, LE u32)                           │
  │  Chunk 0 data     (chunk_len B)  ← raw data + 16-byte tag  │
  │  …                                                         │
  │  Chunk N len      ( 4 B, LE u32)                           │
  │  Chunk N data     (chunk_len B)                            │
  ├────────────────────────────────────────────────────────────┤
  │  EOS sentinel     ( 4 B, all zero)                         │
  └────────────────────────────────────────────────────────────┘
  ```

---

# ❖ Split Piece Format & Integrity (`TFSP`)

Every split piece is self-describing and capped at `<= piece_size` bytes on disk (`header + payload <= piece_size`). During `merge`, Transformer discovers pieces by `TFSP` magic and `split_id`, verifies completeness (`0..total_pieces`), validates each piece's **BLAKE3** payload hash, and verifies the final reconstructed file's **BLAKE3** hash before writing atomically.

```text
┌─────────────────────────────────────────────────────────────┐
│  Magic Bytes         ( 4 B, b"TFSP")                        │
│  Format Version      ( 1 B, 0x01)                           │
│  Tool Version        ( 3 B, [major, minor, patch])          │
│  Split ID            (16 B, random 128-bit group ID)        │
│  Piece Index         ( 8 B, LE u64, 0-based)                │
│  Total Pieces        ( 8 B, LE u64)                         │
│  Original File Size  ( 8 B, LE u64)                         │
│  Original File Hash  (32 B, BLAKE3 digest of full file)     │
│  Piece Payload Hash  (32 B, BLAKE3 digest of this piece)    │
│  Filename Len        ( 2 B, LE u16, 1..=4096)               │
│  Original Filename   ( N B, UTF-8 basename)                 │
├─────────────────────────────────────────────────────────────┤
│  Piece Payload Data  (<= piece_size - header_len bytes)     │
└─────────────────────────────────────────────────────────────┘
```


---




## ❖ Support
If you find this project useful, consider supporting its development:

**Monero (XMR):**
`83eg4LiD5PEWGu6JpU2mfQVmVdNJQfKzGAi5GUGZKBkBdWBaGxxUrifCj1WyiUEtUfLNaxQjcfHDaDtxfZhr7RboPCVvTYf`


## ❖ License

This project is licensed under the **[Unlicense](https://unlicense.org)**. You can view the full license text in the [UNLICENSE](./UNLICENSE) file.
