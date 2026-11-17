use anyhow::{Result, anyhow};

pub mod crypt;
pub mod split_merge;
pub(crate) mod util;

/// Parses human-readable byte size strings such as `"4B"`, `"5KB"`, `"100MB"`, `"2GB"`, or `"1TB"`.
pub fn parse_to_bytes(piece_size: &str) -> Result<u64> {
    let piece_size = piece_size.trim().to_uppercase();

    let (num_str, unit_str) = piece_size.split_at(
        piece_size
            .find(|c: char| !c.is_numeric())
            .ok_or_else(|| anyhow!("No Unit Found"))?,
    );

    let number = num_str
        .parse::<u64>()
        .map_err(|e| anyhow!("Invalid Piece Size Number : {:?}", e))?;

    let multiplier: u64 = match unit_str {
        "B" => 1,
        "KB" => 1_024,
        "MB" => 1_024 * 1_024,
        "GB" => 1_024 * 1_024 * 1_024,
        "TB" => 1_024 * 1_024 * 1_024 * 1_024,
        _ => return Err(anyhow!("Unsupported Unit : {}", unit_str)),
    };

    number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("Piece size overflows u64"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_to_bytes() {
        assert_eq!(parse_to_bytes("10B").unwrap(), 10);
        assert_eq!(parse_to_bytes("2kb").unwrap(), 2048);
        assert_eq!(parse_to_bytes("5MB").unwrap(), 5 * 1024 * 1024);
        assert_eq!(parse_to_bytes("1GB").unwrap(), 1024 * 1024 * 1024);
        assert!(parse_to_bytes("10").is_err());
        assert!(parse_to_bytes("10PB").is_err());
    }
}
