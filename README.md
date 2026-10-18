# 🛠 Transformer

A command-line utility for transforming files from one form to another.

-> Join [Matrix Room](https://matrix.to/#/#transformer:matrix.org)


# ❖ File Splitting Demo :
![transformer file splitting](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_split.gif?raw=true)

# ❖ File Merging Demo :
![transformer file merging](https://github.com/ForTheCommunity/Assets/blob/main/transformer/transformer_merge.gif?raw=true)

## ❖ Key Features

* **File Splitting & Merging**: 
  * Break large files into manageable pieces using custom sizes across multiple units (Bytes, KB, MB, GB, and TB).
  * Reconstruct original files effortlessly from a directory of extracted pieces.
* **Flexible Encryption Modes**:
  * **Password-Based Encryption**: Self-contained file encryption and decryption using direct passwords (`encrypt-pass` and `decrypt-pass`) without requiring external files.
  * **Keystore-Based Management**: Centralized key handling that lets you create a master keystore file protected by a master password to encrypt and decrypt multiple files seamlessly.
* **Performance Optimization**:
  * Configurable chunk/buffer sizes ranging from 1 MB up to 100 MB to optimize processing speed for large files.
* **Robust Security Architecture**:
  * **Secure Interactive Prompts**: Built-in prompts avoid command-line arguments to prevent sensitive passwords from being exposed in shell history.
  * **Argon2 Key Derivation (KDF)**: Protects user passwords against brute-force attacks using a 16-byte cryptographically secure random salt.
  * **AES-256-GCM Encryption (AEAD)**: Ensures complete data confidentiality and integrity validation for both key-wrapping and stream blocks.
  * **Unique Chunk Nonces**: Defends against stream vulnerabilities by mixing a base nonce with an incremental block counter for every chunk.
  * **Seamless Filename Preservation**: Automatically embeds and restores original filenames directly within the encrypted stream.

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
Use the `split` subcommand to break a file into smaller pieces.

```bash
transformer split --file-path <PATH> --piece-size <SIZE> --output <DIRECTORY>
```

**Example:**
```bash
transformer split -f large_video.mp4 -p 100MB -o ./fragments
```

## ✦ Merging Pieces
Use the `merge` subcommand to reconstruct the original file from a directory of pieces.
> **Note:** All pieces must be in the same folder/directory.

```bash
transformer merge --piece <Any Piece> --folder <FOLDER_PATH>
```

**Example:**
```bash
transformer merge -p ~/Downloads/pieces/piece_000 -f ~/Downloads/
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

### 5. Secure Filename Preservation
* The original file name is embedded securely at the very beginning of the plaintext stream (`[filename_len (4 B LE)] ++ [filename bytes]`) before chunk encryption. During decryption, Transformer automatically extracts this header to restore the original filename seamlessly.

### 6. On-Disk File Layout:
* i. Password-Based Encryption Layout (Self-Contained) :
  ```text
  ┌────────────────────────────────────────────────────────────┐
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




## ❖ Support
If you find this project useful, consider supporting its development:

**Monero (XMR):**
`83eg4LiD5PEWGu6JpU2mfQVmVdNJQfKzGAi5GUGZKBkBdWBaGxxUrifCj1WyiUEtUfLNaxQjcfHDaDtxfZhr7RboPCVvTYf`


## ❖ License

This project is licensed under the **[Unlicense](https://unlicense.org)**. You can view the full license text in the [UNLICENSE](./UNLICENSE) file.
