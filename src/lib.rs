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

/// Formats a byte count into a human-readable string such as `"126 B"`, `"50 MB"`, `"154.32 MB"`, `"2.50 GB"`.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;
    const TB: u64 = 1_024 * GB;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format_unit(bytes, KB, "KB")
    } else if bytes < GB {
        format_unit(bytes, MB, "MB")
    } else if bytes < TB {
        format_unit(bytes, GB, "GB")
    } else {
        format_unit(bytes, TB, "TB")
    }
}

fn format_unit(bytes: u64, divisor: u64, unit: &str) -> String {
    if bytes % divisor == 0 {
        format!("{} {unit}", bytes / divisor)
    } else {
        let val = bytes as f64 / divisor as f64;
        format!("{val:.2} {unit}")
    }
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

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(126), "126 B");
        assert_eq!(format_bytes(1024), "1 KB");
        assert_eq!(format_bytes(2048), "2 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5 MB");
        assert_eq!(format_bytes(52428800), "50 MB");
        assert_eq!(format_bytes(161814675), "154.32 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1 GB");
    }
}
