use std::io::{Write, stdout};

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

pub fn progress_bar(current: usize, total: usize) {
    let bar_width = 50;
    let progress = (current as f32 / total as f32).min(1.0);
    let filled_len = (progress * bar_width as f32) as usize;
    let empty_len = bar_width - filled_len;

    let filled_char = "█".repeat(filled_len);
    let empty_char = "░".repeat(empty_len);

    print!(
        "\r     \x1b[32m\x1b[1m• Progress : [{}{}] \x1b[0m {:.1}%",
        filled_char,
        empty_char,
        progress * 1_00.0
    );
    // flushing std output
    let _ = stdout().flush();
}

#[macro_export]
macro_rules! preety_print {
    ($label:expr,$value:expr) => {
        println!(
            "  \x1b[34m\x1b[1m• {:<25} \x1b[0m : \x1b[1m{}\x1b[0m",
            $label, $value
        );
    };
}
