use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

impl SocketState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => SocketState::Established,
            2 => SocketState::SynSent,
            3 => SocketState::SynRecv,
            4 => SocketState::FinWait1,
            5 => SocketState::FinWait2,
            6 => SocketState::TimeWait,
            7 => SocketState::Close,
            8 => SocketState::CloseWait,
            9 => SocketState::LastAck,
            10 => SocketState::Listen,
            11 => SocketState::Closing,
            other => SocketState::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SocketState::Established => "ESTABLISHED",
            SocketState::SynSent => "SYN_SENT",
            SocketState::SynRecv => "SYN_RECV",
            SocketState::FinWait1 => "FIN_WAIT1",
            SocketState::FinWait2 => "FIN_WAIT2",
            SocketState::TimeWait => "TIME_WAIT",
            SocketState::Close => "CLOSED",
            SocketState::CloseWait => "CLOSE_WAIT",
            SocketState::LastAck => "LAST_ACK",
            SocketState::Listen => "LISTEN",
            SocketState::Closing => "CLOSING",
            SocketState::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self,
            SocketState::Established
                | SocketState::SynSent
                | SocketState::SynRecv
                | SocketState::CloseWait
        )
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: SocketState,
    pub inode: u64,
    pub domain: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AppNetworkInfo {
    pub pid: u32,
    pub instance_count: usize,
    pub pids: Vec<u32>,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub connections: Vec<ConnectionInfo>,
    pub upload_speed: f64,    // Bytes per second
    pub download_speed: f64,  // Bytes per second
    pub total_uploaded: u64,  // Total bytes
    pub total_downloaded: u64,// Total bytes
    pub download_history: Vec<f32>,
    pub upload_history: Vec<f32>,
    pub first_seen_id: u64,
    pub is_blocked: bool,
    pub is_proxied: bool,
}

impl AppNetworkInfo {
    pub fn display_name(&self) -> String {
        if self.instance_count > 1 {
            format!("{} ({})", self.name, self.instance_count)
        } else {
            self.name.clone()
        }
    }

    pub fn active_connection_count(&self) -> usize {
        self.connections.iter().filter(|c| c.state.is_active()).count()
    }

    pub fn total_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn has_remote_connection(&self) -> bool {
        self.connections.iter().any(|c| {
            c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip())
        })
    }

    pub fn is_local_only(&self) -> bool {
        !self.has_remote_connection()
    }

    pub fn category_badge(&self) -> (&'static str, &'static str, [f32; 4]) {
        app_category_badge(&self.name)
    }
}

pub fn is_remote_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_link_local()
                && !v4.is_private()
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

pub fn app_category_badge(name: &str) -> (&'static str, &'static str, [f32; 4]) {
    let lower = name.to_lowercase();
    if lower.contains("firefox")
        || lower.contains("chrome")
        || lower.contains("librewolf")
        || lower.contains("brave")
        || lower.contains("edge")
        || lower.contains("browser")
    {
        ("WEB", "Browser", [0.15, 0.70, 0.95, 1.0])
    } else if lower.contains("steam")
        || lower.contains("game")
        || lower.contains("wine")
        || lower.contains("proton")
        || lower.contains("lutris")
        || lower.contains("heroic")
    {
        ("GAME", "Gaming", [0.90, 0.35, 0.85, 1.0])
    } else if lower.contains("discord")
        || lower.contains("ayugram")
        || lower.contains("telegram")
        || lower.contains("slack")
        || lower.contains("signal")
        || lower.contains("element")
    {
        ("CHAT", "Messenger", [0.35, 0.80, 0.45, 1.0])
    } else if lower.contains("code")
        || lower.contains("opencode")
        || lower.contains("sccache")
        || lower.contains("git")
        || lower.contains("cargo")
        || lower.contains("rustc")
        || lower.contains("node")
        || lower.contains("python")
    {
        ("DEV", "Dev Tool", [0.95, 0.65, 0.15, 1.0])
    } else if lower.contains("spotify")
        || lower.contains("vlc")
        || lower.contains("mpv")
        || lower.contains("obs")
        || lower.contains("audio")
    {
        ("MEDIA", "Media", [0.90, 0.30, 0.40, 1.0])
    } else if lower.contains("postgres")
        || lower.contains("mysql")
        || lower.contains("redis")
        || lower.contains("docker")
        || lower.contains("systemd")
        || lower.contains("avahi")
        || lower.contains("adb")
        || lower.contains("daemon")
    {
        ("SYS", "System", [0.55, 0.60, 0.70, 1.0])
    } else {
        ("APP", "App", [0.45, 0.55, 0.80, 1.0])
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

pub fn format_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.1} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.1} KB/s", bytes_per_sec / KB)
    } else if bytes_per_sec > 0.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else {
        "0 B/s".to_string()
    }
}

pub fn well_known_port_desc(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "Submission",
        993 => "IMAPS",
        995 => "POP3S",
        1194 => "OpenVPN",
        3306 => "MySQL",
        3389 => "RDP",
        51820 => "WireGuard",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        9050 | 9051 => "Tor",
        _ => "",
    }
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

    #[test]
    fn test_well_known_ports() {
        assert_eq!(well_known_port_desc(80), "HTTP");
        assert_eq!(well_known_port_desc(443), "HTTPS");
        assert_eq!(well_known_port_desc(53), "DNS");
        assert_eq!(well_known_port_desc(22), "SSH");
        assert_eq!(well_known_port_desc(51820), "WireGuard");
        assert_eq!(well_known_port_desc(9999), "");
    }

    #[test]
    fn test_socket_state() {
        assert_eq!(SocketState::from_u8(1), SocketState::Established);
        assert_eq!(SocketState::from_u8(10), SocketState::Listen);
        assert!(SocketState::Established.is_active());
        assert!(!SocketState::Listen.is_active());
        assert_eq!(SocketState::Established.as_str(), "ESTABLISHED");
    }
}

