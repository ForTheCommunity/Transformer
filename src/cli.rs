use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Splits file to pieces.
    Split {
        /// Path of file to split.
        #[arg(short = 'f', long)]
        file_path: String,
        /// Size of Piece. eg. 4B, 5KB, 6MB etc.
        #[arg(short = 'p', long)]
        piece_size: String,
        /// Output Dir.
        #[arg(short = 'o', long)]
        output: String,
    },
    /// Merge Pieces to a file.
    Merge {
        /// Select a Piece, all pieces of a file should be inside same directory.
        #[arg(short = 'p', long)]
        piece: String,
        /// Output Folder Path, eg. ~/Downloads
        #[arg(short = 'f', long)]
        folder: String,
    },
    /// Encrypt file
    Encrypt {
        /// Path of file to encrypt
        #[arg(short = 'f', long)]
        file: PathBuf,

        /// Keystore
        #[arg(short = 'k', long)]
        keystore: PathBuf,

        /// Output path
        #[arg(short = 'o', long)]
        output: PathBuf,

        /// Chunk size in MB (1-100, default: 1)
        #[arg(short = 'c', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
        chunk_size: u32,
    },
    /// Decrypt file
    Decrypt {
        /// Path of encrypted file,
        #[arg(short = 'f', long)]
        file: PathBuf,

        /// Keystore
        #[arg(short = 'k', long)]
        keystore: PathBuf,

        /// Output path
        #[arg(short = 'o', long)]
        output: PathBuf,

        /// Password of keystore
        password:Option<String>
    },
    /// Encrypt file directly using a password (no keystore needed; self-contained)
    EncryptPass {
        /// Path of file to encrypt
        #[arg(short = 'f', long)]
        file: PathBuf,

        /// Output path
        #[arg(short = 'o', long)]
        output: PathBuf,

        /// Password argument
        #[arg(
            short = 'p',
            long,
            help = "Password used to encrypt/decrypt file",
            long_help = "Password [ Don't pass this argument because it will save your password in shell history. ] A secure password prompt will ask for password even if you don't use this option..."
        )]
        password: Option<String>,

        /// Chunk size in MB (1-100, default: 1)
        #[arg(short = 'c', long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
        chunk_size: u32,
    },
    /// Decrypt a self-contained password-encrypted file
    DecryptPass {
        /// Path of encrypted file
        #[arg(short = 'f', long)]
        file: PathBuf,

        /// Output path
        #[arg(short = 'o', long)]
        output: PathBuf,

        /// Password for decrypting file
        password: Option<String>,
    },
    /// Create Keystore
    CreateKeystore {
        /// Output path for keystore
        #[arg(short = 'o', long)]
        file_path: PathBuf,
    },
}
