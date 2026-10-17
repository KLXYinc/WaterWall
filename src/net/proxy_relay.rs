use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use super::ebpf_redirect::unmap_ebpf_addr;
use crate::utils::{base64_encode, extract_http_host, extract_tls_sni};

pub const LOCAL_RELAY_PORT: u16 = 19180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamProxyKind {
    Socks5,
    HttpConnect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamProxyConfig {
    pub enabled: bool,
    pub kind: UpstreamProxyKind,
    pub server: String,
    pub username: String,
    pub password: String,
}

impl Default for UpstreamProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kind: UpstreamProxyKind::HttpConnect,
            server: String::from("127.0.0.1:1080"),
            username: String::new(),
            password: String::new(),
        }
    }
}

pub struct LocalProxyRelay {
    config: Arc<RwLock<UpstreamProxyConfig>>,
    relayed_count: Arc<AtomicU64>,
}

impl Default for LocalProxyRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProxyRelay {
    pub fn new() -> Self {
        let config = Arc::new(RwLock::new(UpstreamProxyConfig::default()));
        let relayed_count = Arc::new(AtomicU64::new(0));

        // 1. Spawn IPv4 relay listener on 0.0.0.0:19180 (accepts 127.100.<lo>.<hi>:19180)
        spawn_listener_thread(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), LOCAL_RELAY_PORT),
            "waterwall-relay-v4",
            Arc::clone(&config),
            Arc::clone(&relayed_count),
        );

        // 2. Spawn IPv6 loopback relay listener on [::1]:19180 (accepts connect6 redirects)
        spawn_listener_thread(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), LOCAL_RELAY_PORT),
            "waterwall-relay-v6",
            Arc::clone(&config),
            Arc::clone(&relayed_count),
        );

        Self {
            config,
            relayed_count,
        }
    }

    pub fn update_config(&self, new_cfg: UpstreamProxyConfig) {
        if let Ok(mut c) = self.config.write() {
            if *c != new_cfg {
                *c = new_cfg;
            }
        }
    }

    pub fn relayed_connections(&self) -> u64 {
        self.relayed_count.load(Ordering::Relaxed)
    }
}

fn spawn_listener_thread(
    bind_addr: SocketAddr,
    thread_name: &str,
    cfg_clone: Arc<RwLock<UpstreamProxyConfig>>,
    cnt_clone: Arc<AtomicU64>,
) {
    let _ = thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let Ok(listener) = TcpListener::bind(bind_addr) else {
                return;
            };
            for incoming in listener.incoming().flatten() {
                let mut cfg = cfg_clone.read().map(|c| c.clone()).unwrap_or_default();
                if !cfg.enabled || cfg.server.trim().is_empty() {
                    if let (_, Some(disk_cfg)) = super::ipc::scan_saved_config_proxied_state() {
                        cfg = disk_cfg;
                    }
                }
                if !cfg.enabled || cfg.server.trim().is_empty() {
                    continue;
                }
                let cnt = Arc::clone(&cnt_clone);
                thread::spawn(move || {
                    let _ = handle_relayed_client(incoming, &cfg, &cnt);
                });
            }
        });
}

fn handle_relayed_client(
    mut client: TcpStream,
    cfg: &UpstreamProxyConfig,
    cnt: &AtomicU64,
) -> Result<(), String> {
    let _ = client.set_nodelay(true);

    // 1. Check if eBPF encoded an IPv4 slot in 127.100.<lo>.<hi>
    let slot_dst = resolve_original_destination(&client);

    // 2. Peek/read initial bytes from client (up to 400ms) to extract TLS SNI or HTTP Host!
    let _ = client.set_read_timeout(Some(Duration::from_millis(400)));
    let mut initial_buf = [0u8; 2048];
    let n_read = client.read(&mut initial_buf).unwrap_or(0);
    let initial_data = &initial_buf[..n_read];

    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));

    // Determine target host:port (prefer TLS SNI or HTTP Host so both IPv4 & IPv6 work seamlessly!)
    let target_host_port = if let Some(sni) = extract_tls_sni(initial_data) {
        let port = slot_dst.map(|d| d.port()).unwrap_or(443);
        format!("{}:{}", sni, port)
    } else if let Some(http_host) = extract_http_host(initial_data) {
        if http_host.contains(':') {
            http_host
        } else {
            let port = slot_dst.map(|d| d.port()).unwrap_or(80);
            format!("{}:{}", http_host, port)
        }
    } else if let Some(dst) = slot_dst {
        format!("{}:{}", dst.ip(), dst.port())
    } else {
        return Err("No SNI/Host or eBPF slot found for connection".to_string());
    };

    // 3. Connect to the upstream proxy server (e.g. geo.iproyal.com:12321)
    let upstream_addr = cfg
        .server
        .trim()
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolve '{}': {}", cfg.server, e))?
        .find(|a| a.is_ipv4())
        .or_else(|| cfg.server.trim().to_socket_addrs().ok()?.next())
        .ok_or_else(|| format!("No IP for proxy '{}'", cfg.server))?;

    if upstream_addr.ip().is_loopback() && upstream_addr.port() == LOCAL_RELAY_PORT {
        return Err("Upstream cannot be local relay port".to_string());
    }

    let mut upstream = TcpStream::connect_timeout(&upstream_addr, Duration::from_secs(8))
        .map_err(|e| format!("Connect {}: {}", upstream_addr, e))?;
    let _ = upstream.set_nodelay(true);
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(30)));

    // 4. Perform upstream proxy handshake (HTTP CONNECT or SOCKS5)
    match cfg.kind {
        UpstreamProxyKind::HttpConnect => {
            handshake_http_connect(&mut upstream, &target_host_port, &cfg.username, &cfg.password)?;
        }
        UpstreamProxyKind::Socks5 => {
            handshake_socks5(&mut upstream, &target_host_port, &cfg.username, &cfg.password)?;
        }
    }

    // 5. Forward any initial bytes (TLS ClientHello / HTTP request) that we read during SNI/Host detection
    if !initial_data.is_empty() {
        upstream
            .write_all(initial_data)
            .map_err(|e| format!("Forward initial data: {}", e))?;
        let _ = upstream.flush();
    }

    cnt.fetch_add(1, Ordering::Relaxed);

    // 6. Bidirectional TCP stream forwarding
    let mut client_reader = client.try_clone().map_err(|e| e.to_string())?;
    let mut upstream_writer = upstream.try_clone().map_err(|e| e.to_string())?;

    thread::spawn(move || {
        let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
    });

    let _ = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    Ok(())
}

fn resolve_original_destination(client: &TcpStream) -> Option<SocketAddr> {
    client.local_addr().ok().and_then(unmap_ebpf_addr)
}

fn handshake_http_connect(
    stream: &mut TcpStream,
    target_host_port: &str,
    user: &str,
    pass: &str,
) -> Result<(), String> {
    let mut req = format!(
        "CONNECT {0} HTTP/1.1\r\nHost: {0}\r\nProxy-Connection: Keep-Alive\r\n",
        target_host_port
    );

    if !user.is_empty() || !pass.is_empty() {
        let cred = format!("{}:{}", user, pass);
        let b64 = base64_encode(cred.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("HTTP CONNECT write: {}", e))?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut resp = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while resp.len() < 4096 {
        let n = stream
            .read(&mut byte)
            .map_err(|e| format!("HTTP CONNECT read: {}", e))?;
        if n == 0 {
            break;
        }
        resp.push(byte[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let resp_str = String::from_utf8_lossy(&resp);
    let first_line = resp_str.lines().next().unwrap_or("");
    if first_line.contains(" 200 ") || first_line.ends_with(" 200") {
        Ok(())
    } else {
        Err(format!("Proxy rejected CONNECT: {}", first_line))
    }
}

fn handshake_socks5(
    stream: &mut TcpStream,
    target_host_port: &str,
    user: &str,
    pass: &str,
) -> Result<(), String> {
    let use_auth = !user.is_empty() || !pass.is_empty();
    let greeting: &[u8] = if use_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting).map_err(|e| e.to_string())?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).map_err(|e| e.to_string())?;
    if method_resp[1] == 0x02 {
        let ub = user.as_bytes();
        let pb = pass.as_bytes();
        let mut auth_pkt = Vec::with_capacity(3 + ub.len() + pb.len());
        auth_pkt.push(0x01);
        auth_pkt.push(ub.len() as u8);
        auth_pkt.extend_from_slice(ub);
        auth_pkt.push(pb.len() as u8);
        auth_pkt.extend_from_slice(pb);
        stream.write_all(&auth_pkt).map_err(|e| e.to_string())?;
        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).map_err(|e| e.to_string())?;
        if auth_resp[1] != 0x00 {
            return Err("SOCKS5 auth failed".to_string());
        }
    }

    let (host, port_s) = target_host_port.rsplit_once(':').ok_or("Invalid target")?;
    let port: u16 = port_s.parse().map_err(|_| "Invalid port")?;
    let pb = port.to_be_bytes();

    // Domain-based SOCKS5 ATYP 0x03 (works for both domain names and IP strings!)
    let hb = host.as_bytes();
    let mut req = Vec::with_capacity(7 + hb.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, hb.len() as u8]);
    req.extend_from_slice(hb);
    req.extend_from_slice(&pb);
    stream.write_all(&req).map_err(|e| e.to_string())?;

    let mut reply_hdr = [0u8; 4];
    stream.read_exact(&mut reply_hdr).map_err(|e| e.to_string())?;
    if reply_hdr[1] != 0x00 {
        return Err(format!("SOCKS5 connect error {}", reply_hdr[1]));
    }
    let skip_len = match reply_hdr[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut dlen = [0u8; 1];
            stream.read_exact(&mut dlen).map_err(|e| e.to_string())?;
            dlen[0] as usize + 2
        }
        _ => 6,
    };
    let mut discard = vec![0u8; skip_len];
    let _ = stream.read_exact(&mut discard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_live_iproyal_upstream_proxy_tunnel() {
        let (_, cfg_opt) = super::super::ipc::scan_saved_config_proxied_state();
        let Some(cfg) = cfg_opt else { return };
        let Ok(mut addrs) = cfg.server.to_socket_addrs() else { return };
        let Some(proxy_addr) = addrs.find(|a| a.is_ipv4()) else { return };
        let Ok(mut stream) = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(5)) else { return };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        handshake_http_connect(&mut stream, "api.ipify.org:80", &cfg.username, &cfg.password)
            .expect("HTTP CONNECT handshake to IPRoyal proxy should succeed");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").trim();
        println!("IPRoyal Tunneled Public IP Response: {}", body);
        assert!(!body.is_empty(), "Expected public IP from tunneled request");
    }
}
