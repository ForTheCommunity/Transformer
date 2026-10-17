use clap::Parser;
use transformer::{
    cli::{Cli, Commands},
    crypt::{create_ks, decyrpt_file_ks, decyrpt_file_wp, encrypt_file_ks, encyrpt_file_wp},
    merge::merge,
    preety_print,
    split::split_file,
};

mod cli;

fn main() {
    let cli_args = Cli::parse();

    match &cli_args.command {
        Some(Commands::Split {
            file_path,
            piece_size,
            output,
        }) => {
            match split_file(file_path, piece_size, output) {
                Ok(_) => {}
                Err(e) => {
                    preety_print!("Error", e);
                }
            };
        }

        Some(Commands::Merge { piece, folder }) => match merge(piece, folder) {
            Ok(_) => {}
            Err(e) => {
                preety_print!("Error", e);
            }
        },

        Some(Commands::Encrypt {
            file,
            keystore,
            output,
            chunk_size,
        }) => {
            let chunk_bytes = *chunk_size as usize * 1024 * 1024;
            if let Err(e) = encrypt_file_ks(keystore, file, output, chunk_bytes, None) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::Decrypt {
            file,
            keystore,
            output,
        }) => {
            if let Err(e) = decyrpt_file_ks(keystore, file, output) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::EncryptPass {
            file,
            output,
            password,
            chunk_size,
        }) => {
            let chunk_bytes = *chunk_size as usize * 1024 * 1024;
            if let Err(e) = encyrpt_file_wp(file, output, password, chunk_bytes) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::DecryptPass { file, output }) => {
            if let Err(e) = decyrpt_file_wp(file, output) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::CreateKeystore { file_path }) => {
            if let Err(e) = create_ks(file_path) {
                eprintln!("  {}", e)
            }
        }

        None => {
            preety_print!("Error", "Use a valid command !!!");
        }
    }
}
