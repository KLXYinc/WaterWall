use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::socket::{Protocol, SocketState};

pub struct ProcSocket {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: SocketState,
    pub inode: u64,
}

pub struct ProcessMetadata {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub inodes: Vec<u64>,
    pub rchar: u64,
    pub wchar: u64,
}

pub fn parse_hex_ipv4(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    // Linux procfs outputs IPv4 in host endian / little endian
    let octets = val.to_le_bytes();
    Some(Ipv4Addr::from(octets))
}

pub fn parse_hex_ipv6(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    // Four 32-bit words in host endian
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(chunk, 16).ok()?;
        let word_bytes = word.to_ne_bytes();
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    Some(Ipv6Addr::from(octets))
}

pub fn parse_socket_addr(raw: &str, is_v6: bool) -> Option<SocketAddr> {
    let mut parts = raw.split(':');
    let ip_str = parts.next()?;
    let port_str = parts.next()?;
    let port = u16::from_str_radix(port_str, 16).ok()?;

    if is_v6 {
        let ip = parse_hex_ipv6(ip_str)?;
        Some(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        let ip = parse_hex_ipv4(ip_str)?;
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    }
}

pub fn parse_proc_net_file(path: &str, protocol: Protocol, is_v6: bool) -> Vec<ProcSocket> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut sockets = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local_addr = match parse_socket_addr(fields[1], is_v6) {
            Some(a) => a,
            None => continue,
        };

        let remote_addr = match parse_socket_addr(fields[2], is_v6) {
            Some(a) => a,
            None => continue,
        };

        let raw_state = u8::from_str_radix(fields[3], 16).unwrap_or(0);
        let state = if protocol == Protocol::Udp {
            // For UDP, state field is not TCP state machine
            if remote_addr.port() != 0 {
                SocketState::Established
            } else {
                SocketState::Listen
            }
        } else {
            SocketState::from_u8(raw_state)
        };

        let inode = match fields[9].parse::<u64>() {
            Ok(i) => i,
            Err(_) => continue,
        };

        sockets.push(ProcSocket {
            protocol,
            local_addr,
            remote_addr,
            state,
            inode,
        });
    }

    sockets
}

pub fn scan_all_sockets() -> Vec<ProcSocket> {
    let mut all = Vec::with_capacity(128);
    all.extend(parse_proc_net_file("/proc/net/tcp", Protocol::Tcp, false));
    all.extend(parse_proc_net_file("/proc/net/tcp6", Protocol::Tcp, true));
    all.extend(parse_proc_net_file("/proc/net/udp", Protocol::Udp, false));
    all.extend(parse_proc_net_file("/proc/net/udp6", Protocol::Udp, true));
    all
}

pub fn scan_process_metadata() -> HashMap<u32, ProcessMetadata> {
    let mut procs = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return procs,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        let pid = match name_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let pid_path = entry.path();

        // 1. Process name (/proc/[pid]/comm)
        let comm_path = pid_path.join("comm");
        let name = fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| name_str.to_string());

        // 2. Executable path (/proc/[pid]/exe)
        let exe_path_buf = pid_path.join("exe");
        let exe_path = fs::read_link(&exe_path_buf)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // 3. Command line (/proc/[pid]/cmdline)
        let cmdline_path = pid_path.join("cmdline");
        let cmdline = fs::read_to_string(&cmdline_path)
            .map(|s| s.replace('\0', " ").trim().to_string())
            .unwrap_or_default();

        // 4. Inodes from /proc/[pid]/fd
        let mut inodes = Vec::new();
        let fd_dir_path = pid_path.join("fd");
        if let Ok(fd_entries) = fs::read_dir(&fd_dir_path) {
            for fd_entry in fd_entries.flatten() {
                if let Ok(target) = fs::read_link(fd_entry.path()) {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                        let inner = &target_str[8..target_str.len() - 1];
                        if let Ok(inode) = inner.parse::<u64>() {
                            inodes.push(inode);
                        }
                    }
                }
            }
        }

        // 5. I/O counters (/proc/[pid]/io)
        let mut rchar = 0u64;
        let mut wchar = 0u64;
        let io_path = pid_path.join("io");
        if let Ok(io_content) = fs::read_to_string(&io_path) {
            for line in io_content.lines() {
                if let Some(rest) = line.strip_prefix("rchar: ") {
                    rchar = rest.trim().parse::<u64>().unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("wchar: ") {
                    wchar = rest.trim().parse::<u64>().unwrap_or(0);
                }
            }
        }

        procs.insert(
            pid,
            ProcessMetadata {
                pid,
                name,
                exe_path,
                cmdline,
                inodes,
                rchar,
                wchar,
            },
        );
    }

    procs
}

pub struct SystemNetDev {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub fn read_system_net_dev() -> SystemNetDev {
    let mut rx = 0u64;
    let mut tx = 0u64;

    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            let mut parts = line.split_whitespace();
            let iface = parts.next().unwrap_or("");
            // Exclude loopback
            if iface.starts_with("lo:") {
                continue;
            }

            if let Some(rx_str) = parts.next() {
                rx += rx_str.parse::<u64>().unwrap_or(0);
            }
            // Skip 7 fields: packets errs drop fifo frame compressed multicast
            for _ in 0..7 {
                parts.next();
            }
            if let Some(tx_str) = parts.next() {
                tx += tx_str.parse::<u64>().unwrap_or(0);
            }
        }
    }

    SystemNetDev {
        rx_bytes: rx,
        tx_bytes: tx,
    }
}

#[derive(Clone, Debug)]
pub struct VpnInterfaceInfo {
    pub name: String,
    pub kind: &'static str,
    pub is_up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Scans `/proc/net/dev` and `/sys/class/net` for active VPN / Tunnel interfaces
pub fn scan_vpn_interfaces() -> Vec<VpnInterfaceInfo> {
    let mut list = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return list;
    };

    for line in content.lines().skip(2) {
        let Some((iface_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let iface = iface_raw.trim();
        let lower = iface.to_lowercase();

        let kind = if lower.starts_with("wg") {
            Some("WireGuard")
        } else if lower.starts_with("tailscale") {
            Some("Tailscale")
        } else if lower.starts_with("proton") || lower.starts_with("pvpn") {
            Some("ProtonVPN")
        } else if lower.starts_with("nordlynx") {
            Some("NordLynx")
        } else if lower.starts_with("tun") || lower.starts_with("tap") || lower.starts_with("utun") {
            Some("OpenVPN / TUN")
        } else if std::path::Path::new(&format!("/sys/class/net/{}/tun_flags", iface)).exists() {
            Some("TUN/TAP Tunnel")
        } else {
            None
        };

        let Some(vpn_kind) = kind else {
            continue;
        };

        let mut parts = rest.split_whitespace();
        let rx_bytes = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        for _ in 0..7 {
            parts.next();
        }
        let tx_bytes = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);

        let flags_path = format!("/sys/class/net/{}/flags", iface);
        let is_up = fs::read_to_string(flags_path)
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .map(|f| (f & 0x1) != 0)
            .unwrap_or(true);

        list.push(VpnInterfaceInfo {
            name: iface.to_string(),
            kind: vpn_kind,
            is_up,
            rx_bytes,
            tx_bytes,
        });
    }

    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_ipv4() {
        // 0100007F is 127.0.0.1
        let ip = parse_hex_ipv4("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));

        // 00000000 is 0.0.0.0
        let ip_zero = parse_hex_ipv4("00000000").unwrap();
        assert_eq!(ip_zero, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_hex_ipv6() {
        // ::1 in host-endian words representation
        let ip = parse_hex_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_parse_socket_addr() {
        // 127.0.0.1:80 (80 = 0x0050)
        let addr = parse_socket_addr("0100007F:0050", false).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 80);

        // ::1:443 (443 = 0x01BB)
        let addr6 = parse_socket_addr("00000000000000000000000001000000:01BB", true).unwrap();
        assert_eq!(addr6.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addr6.port(), 443);
    }

    #[test]
    fn test_live_socket_and_process_scan() {
        let sockets = scan_all_sockets();
        // There should be sockets present on any running Linux desktop
        println!("Scanned {} live sockets on system", sockets.len());

        let procs = scan_process_metadata();
        println!("Scanned {} live processes in /proc", procs.len());
        assert!(!procs.is_empty());

        // Check that current process is found
        let my_pid = std::process::id();
        assert!(procs.contains_key(&my_pid));
    }
}

