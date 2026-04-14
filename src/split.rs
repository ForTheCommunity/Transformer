use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use anyhow::{Result, anyhow};

use crate::parse_to_bytes;

pub fn split_file(file_path: &str, piece_size: &str, output: &str) -> Result<()> {
    let piece_size = parse_to_bytes(piece_size)?;
    let file_path = Path::new(file_path);
    let file = File::open(file_path)?;
    if file_path.is_dir() {
        return Err(anyhow!("Give a File Path not a Directory Path !!!"));
    }
    let file_name = file_path
        .file_name()
        .and_then(|f_n| f_n.to_str())
        .ok_or_else(|| anyhow!("Invalid Filename, unable to extract filename !!!"))?;

    let file_size = file.metadata()?.len() as usize;

    println!("  -> File Size in Bytes -> {}", file_size);
    println!("  -> Piece Size in Bytes -> {}", piece_size);

    // check if piece_size is greator than file size or not.
    if piece_size > file_size {
        return Err(anyhow!("Piece size is greator than file size !!!"));
    }

    if piece_size == 0 {
        return Err(anyhow!("Piece size Can't be Zero !!!"));
    }

    // estimating total pieces
    let total_pieces = (file_size + piece_size - 1) / piece_size;
    println!("  -> Total Estimated Pieces : {}", total_pieces);
    // width for saving pieces name in lexographical order.
    let width = total_pieces.to_string().len();

    let mut reader = BufReader::new(file);

    // Buffer
    let buffer_size = parse_to_bytes("1MB")?;
    let mut buffer = vec![0; buffer_size];

    // piece count
    let mut piece_count: usize = 0;
    // Bytes read for current piece.
    let mut bytes_read = 0usize;

    // creating first piece.
    let mut writer = create_piece(file_name, output, piece_count, width)?;

    loop {
        // remaining in piece.
        let remaining = piece_size - bytes_read;
        let bytes_to_read = remaining.min(buffer_size);

        let n = reader.read(&mut buffer[..bytes_to_read])?;
        if n == 0 {
            break;
        }

        writer.write_all(&buffer[..n])?;
        bytes_read += n;

        // If this piece is filled and there are more pieces expected, create a new one.
        if bytes_read >= piece_size && (piece_count + 1) < total_pieces {
            piece_count += 1;
            bytes_read = 0;
            writer = create_piece(file_name, output, piece_count, width)?;
        }
    }

    Ok(())
}

fn create_piece(
    filename: &str,
    destination_path: &str,
    index: usize,
    width: usize,
) -> Result<BufWriter<File>> {
    let file_name = format!("{}_piece_{:0width$}", filename, index, width = width);
    let path = Path::new(destination_path).join(file_name);
    let file = File::create(path)?;

    Ok(BufWriter::new(file))
}
