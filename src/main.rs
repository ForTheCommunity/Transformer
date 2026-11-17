use clap::{CommandFactory, Parser};
use transformer::preety_print;

use crate::{
    bin_helper::{
        create_ks, dfwkp_bin_helper, dfwks_bin_helper, efwkp_bin_helper, efwks_bin_helper,
        merge_bin_helper, split_bin_helper,
    },
    cli::{Cli, Commands},
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
            if let Err(e) = split_bin_helper(file_path, piece_size, output) {
                preety_print!("Error", e);
            }
        }

        Some(Commands::Merge { piece, folder }) => {
            if let Err(e) = merge_bin_helper(piece, folder) {
                preety_print!("Error", e);
            }
        }

        Some(Commands::Encrypt {
            file,
            keystore,
            output,
            chunk_size,
            delete,
        }) => {
            let chunk_bytes = *chunk_size as usize * 1024 * 1024;
            if let Err(e) = efwks_bin_helper(keystore, file, output, chunk_bytes, None, *delete) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::Decrypt {
            file,
            keystore,
            output,
            password,
            delete,
        }) => {
            if let Err(e) = dfwks_bin_helper(keystore, file, output, password, *delete) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::EncryptPass {
            file,
            output,
            password,
            chunk_size,
            delete
        }) => {
            let chunk_bytes = *chunk_size as usize * 1024 * 1024;
            if let Err(e) = efwkp_bin_helper(file, output, password, chunk_bytes,*delete) {
                eprintln!("  {}", e)
            }
        }

        Some(Commands::DecryptPass {
            file,
            output,
            password,
            delete
        }) => {
            if let Err(e) = dfwkp_bin_helper(file, output, password,*delete) {
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
