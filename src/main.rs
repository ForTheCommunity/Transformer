use clap::{CommandFactory, Parser};
use transformer::{
    cli::{Cli, Commands},
    merge::merge,
    preety_print,
    split::split_file,
};

use crate::bin_helper::{
    create_ks, dfwkp_bin_helper, dfwks_bin_helper, efwkp_bin_helper, efwks_bin_helper,
};

mod bin_helper;
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
            if let Err(e) = efwks_bin_helper(keystore, file, output, chunk_bytes, None) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::Decrypt {
            file,
            keystore,
            output,
            password,
        }) => {
            if let Err(e) = dfwks_bin_helper(keystore, file, output, password) {
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
            if let Err(e) = efwkp_bin_helper(file, output, password, chunk_bytes) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::DecryptPass {
            file,
            output,
            password,
        }) => {
            if let Err(e) = dfwkp_bin_helper(file, output, password) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::CreateKeystore { file_path }) => {
            if let Err(e) = create_ks(file_path) {
                eprintln!("  {}", e)
            }
        }

        None => Cli::command().print_help().expect("failed to print help"),
    }
}
