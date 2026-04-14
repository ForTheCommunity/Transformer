use std::{
    fs::{File, read_dir},
    io::{BufReader, BufWriter, copy},
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};

pub fn merge(piece_path: &str, output: &str) -> Result<()> {
    let piece_path = Path::new(piece_path);

    // file name of a piece.
    let file_name = piece_path
        .file_name()
        .and_then(|f_n| f_n.to_str())
        .ok_or_else(|| anyhow!(""))?;
    // extracting orignal filename from piece name.
    // <FILE_NAME>_piece_<PIECE_INDEX>
    let orignal_filename = file_name
        .split("_piece_")
        .nth(0)
        .ok_or_else(|| anyhow!("Unable to extract filename from piece name !!!"))?;

    println!("ORIG FN -> {}", orignal_filename);

    // path of folder where pieces are located.
    let pieces_dir = read_dir(piece_path.parent().unwrap())?;

    let mut pieces_list: Vec<PathBuf> = Vec::new();

    for entry in pieces_dir {
        let entry = entry?;
        let file_name = entry.file_name().into_string().map_err(|e| anyhow!("Filename(OsString) contains invalid UTF-8 & cannot be converted to str. Error -> {:?}",e))?;
        if file_name.contains(orignal_filename) {
            pieces_list.push(entry.path());
        }
    }

    // Pieces are named with leading zeros (e.g., piece_00, piece_01),
    // so lexicographical sort matches numerical order.
    pieces_list.sort();

    let output_file = File::create(Path::new(output).join(orignal_filename))?;
    let mut writer = BufWriter::new(output_file);

    for a_piece in pieces_list {
        let piece_file = File::open(a_piece)?;
        let mut reader = BufReader::new(piece_file);

        copy(&mut reader, &mut writer)?;
    }

    Ok(())
}
