use std::fs;
use std::path::PathBuf;

fn format_scaled_unit(value: f64, suffix: &str) -> Option<String> {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if value >= GB {
        Some(format!("{:.2} GB{}", value / GB, suffix))
    } else if value >= MB {
        Some(format!("{:.1} MB{}", value / MB, suffix))
    } else if value >= KB {
        Some(format!("{:.1} KB{}", value / KB, suffix))
    } else {
        None
    }
}

pub fn format_bytes(bytes: u64) -> String {
    format_scaled_unit(bytes as f64, "").unwrap_or_else(|| format!("{} B", bytes))
}

pub fn format_speed(bytes_per_sec: f64) -> String {
    if let Some(scaled) = format_scaled_unit(bytes_per_sec, "/s") {
        scaled
    } else if bytes_per_sec > 0.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else {
        "0 B/s".to_string()
    }
}

/// Safe UTF-8 character truncation (never panics on multi-byte characters).
pub fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let take_n = max_chars.saturating_sub(2).max(1);
        let prefix: String = s.chars().take(take_n).collect();
        format!("{}..", prefix)
    }
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Primary path for saving and loading the user's Flow Graph configuration.
pub fn graph_save_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(format!("{}/.config/waterwall/flow_graph.cfg", home))
    } else {
        PathBuf::from("waterwall_graph.cfg")
    }
}

/// Candidate paths searched by the root daemon to find user Flow Graph configurations.
pub fn graph_save_candidates() -> Vec<PathBuf> {
    let mut paths = vec![graph_save_path(), PathBuf::from("waterwall_graph.cfg")];
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            paths.push(entry.path().join(".config/waterwall/flow_graph.cfg"));
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_speed() {
        assert_eq!(format_speed(0.0), "0 B/s");
        assert_eq!(format_speed(500.0), "500 B/s");
        assert_eq!(format_speed(1024.0), "1.0 KB/s");
        assert_eq!(format_speed(1572864.0), "1.5 MB/s");
    }
}
