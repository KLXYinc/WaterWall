use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parses a procfs 8-hex-digit IPv4 address (little-endian host order).
pub fn parse_hex_ipv4(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex_str, 16).ok()?;
    Some(Ipv4Addr::from(val.to_le_bytes()))
}

/// Parses a procfs 32-hex-digit IPv6 address (four 32-bit words in host endian).
pub fn parse_hex_ipv6(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(chunk, 16).ok()?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
    }
    Some(Ipv6Addr::from(octets))
}

/// Parses a procfs `<hex_ip>:<hex_port>` socket endpoint.
pub fn parse_socket_addr(raw: &str, is_v6: bool) -> Option<SocketAddr> {
    let (ip_str, port_str) = raw.split_once(':')?;
    let port = u16::from_str_radix(port_str, 16).ok()?;

    if is_v6 {
        Some(SocketAddr::new(IpAddr::V6(parse_hex_ipv6(ip_str)?), port))
    } else {
        Some(SocketAddr::new(IpAddr::V4(parse_hex_ipv4(ip_str)?), port))
    }
}

/// Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello packet.
pub fn extract_tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 || buf[0] != 0x16 || buf[1] != 0x03 || buf[5] != 0x01 {
        return None;
    }
    let mut pos = 43;
    if pos >= buf.len() {
        return None;
    }
    let sess_len = buf[pos] as usize;
    pos += 1 + sess_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let suites_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + suites_len;
    if pos + 1 > buf.len() {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = buf[pos + 2];
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            if name_type == 0 && pos + 5 + name_len <= pos + ext_len {
                if let Ok(sni) = std::str::from_utf8(&buf[pos + 5..pos + 5 + name_len]) {
                    if !sni.is_empty() {
                        return Some(sni.to_string());
                    }
                }
            }
        }
        pos += ext_len;
    }
    None
}

/// Extracts the `Host:` header from an HTTP request.
pub fn extract_http_host(buf: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(&buf[..buf.len().min(1024)]).ok()?;
    for line in s.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let h = rest.trim();
            if !h.is_empty() {
                return Some(h.to_string());
            }
        }
    }
    None
}

/// Parses proxy strings in formats:
/// - `http://user:pass@host:port` / `https://user:pass@host:port` / `socks5://user:pass@host:port`
/// - `user:pass@host:port`
/// - `host:port:user:pass`
pub fn parse_proxy_url(raw: &str) -> Option<(Option<usize>, String, String, String)> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }

    let mut proto_idx = None;
    if let Some((scheme, rest)) = s.split_once("://") {
        let sc = scheme.to_lowercase();
        proto_idx = match sc.as_str() {
            "http" | "https" => Some(1),
            "socks5" | "socks5h" | "socks" => Some(0),
            "ss" | "shadowsocks" => Some(3),
            _ => None,
        };
        s = rest.trim_end_matches('/');
    } else {
        s = s.trim_end_matches('/');
    }

    if let Some((auth, host_port)) = s.rsplit_once('@') {
        let host_port = host_port.trim().to_string();
        if host_port.is_empty() {
            return None;
        }
        let (user, pass) = match auth.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (auth.to_string(), String::new()),
        };
        return Some((proto_idx, host_port, user, pass));
    }

    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() == 4 && parts[1].parse::<u16>().is_ok() {
        let host_port = format!("{}:{}", parts[0], parts[1]);
        return Some((
            proto_idx,
            host_port,
            parts[2].to_string(),
            parts[3].to_string(),
        ));
    }

    if proto_idx.is_some() && s.contains(':') {
        return Some((proto_idx, s.to_string(), String::new(), String::new()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iproyal_proxy_url() {
        let input = "http://6Rnh55e5IfbFB38g:cJUBMuk8d9aKDp1v_country-de_session-1c3Xnf55_lifetime-168h@geo.iproyal.com:12321";
        let (proto, srv, user, pass) = parse_proxy_url(input).expect("should parse proxy URL");
        assert_eq!(proto, Some(1));
        assert_eq!(srv, "geo.iproyal.com:12321");
        assert_eq!(user, "6Rnh55e5IfbFB38g");
        assert_eq!(
            pass,
            "cJUBMuk8d9aKDp1v_country-de_session-1c3Xnf55_lifetime-168h"
        );
    }

    #[test]
    fn test_parse_hex_ipv4() {
        assert_eq!(parse_hex_ipv4("0100007F").unwrap(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(parse_hex_ipv4("00000000").unwrap(), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_hex_ipv6() {
        assert_eq!(
            parse_hex_ipv6("00000000000000000000000001000000").unwrap(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_parse_socket_addr() {
        let addr = parse_socket_addr("0100007F:0050", false).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 80);

        let addr6 = parse_socket_addr("00000000000000000000000001000000:01BB", true).unwrap();
        assert_eq!(addr6.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(addr6.port(), 443);
    }
}
