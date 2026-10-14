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
    /// Encrypt file/s
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
    },
    /// Decrypt file/s
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
    },
}
