use anyhow::{Result, anyhow};

pub mod cli;
pub mod merge;
pub mod split;

pub fn parse_to_bytes(piece_size: &str) -> Result<usize> {
    let piece_size = piece_size.trim().to_uppercase();

    let (num_str, unit_str) = piece_size.split_at(
        piece_size
            .find(|c: char| !c.is_numeric())
            .ok_or(anyhow!("No Unit Found"))?,
    );

    let number = num_str
        .parse::<usize>()
        .map_err(|e| anyhow!("Invalid Piece Size Number : {:?}", e))?;

    let multiplier: usize = match unit_str {
        "B" => 1,
        "KB" => 1_024,
        "MB" => 1_024 * 1_024,
        "GB" => 1_024 * 1_024 * 1_024,
        "TB" => 1_024 * 1_024 * 1_024 * 1_024,
        _ => return Err(anyhow!(format!("Unsupported Unit : {}", unit_str))),
    };

    Ok(number * multiplier)
}
