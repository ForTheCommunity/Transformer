use clap::Parser;
use transformer::{
    cli::{Cli, Commands},
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

        None => {
            preety_print!("Error", "Use a valid command !!!");
        }
    }
}
