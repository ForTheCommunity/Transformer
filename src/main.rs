use clap::Parser;
use transformer::{
    cli::{Cli, Commands},
    merge::merge,
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
                    println!("  !!! Error : {}", e)
                }
            };
        }

        Some(Commands::Merge { piece, folder }) => match merge(piece, folder) {
            Ok(_) => {}
            Err(e) => {
                println!("  !!! Error : {}", e)
            }
        },

        None => {
            println!("Use a valid command !!!")
        }
    }
}
