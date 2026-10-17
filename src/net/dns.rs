use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::process::Command;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Instant;

use super::socket::is_remote_ip;

pub const MAX_DNS_EVENTS: usize = 250;

/// Live DNS resolution or query event tracked across the system
#[derive(Clone, Debug)]
pub struct DnsEvent {
    pub id: u64,
    pub domain: String,
    pub ip: IpAddr,
    pub app_name: String,
    pub protocol: &'static str,
    pub latency_ms: f32,
    pub age_secs: u64,
    pub created_at: Instant,
}

struct DnsLookupReq {
    ip: IpAddr,
    app_name: String,
    protocol: &'static str,
}

#[derive(Clone)]
pub struct DnsResolver {
    /// Maps IP -> Some(resolved_domain) or None (if lookup completed with no PTR record)
    cache: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
    events: Arc<RwLock<VecDeque<DnsEvent>>>,
    request_tx: Sender<DnsLookupReq>,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    pub fn new() -> Self {
        let mut initial_cache: HashMap<IpAddr, Option<String>> = HashMap::new();

        // Pre-populate well-known resolvers and loopback
        for (ip_str, host) in [
            ("127.0.0.1", "localhost"),
            ("127.0.0.53", "systemd-resolved.local"),
            ("::1", "localhost"),
            ("1.1.1.1", "one.one.one.one"),
            ("1.0.0.1", "one.one.one.one"),
            ("8.8.8.8", "dns.google"),
            ("8.8.4.4", "dns.google"),
            ("9.9.9.9", "dns.quad9.net"),
            ("208.67.222.222", "resolver1.opendns.com"),
        ] {
            if let Ok(ip) = ip_str.parse() {
                initial_cache.insert(ip, Some(host.to_string()));
            }
        }

        // Load /etc/hosts mappings
        load_etc_hosts(&mut initial_cache);

        let cache = Arc::new(RwLock::new(initial_cache));
        let events = Arc::new(RwLock::new(VecDeque::with_capacity(MAX_DNS_EVENTS)));
        let (request_tx, request_rx) = mpsc::channel::<DnsLookupReq>();

        let cache_clone = Arc::clone(&cache);
        let events_clone = Arc::clone(&events);

        thread::Builder::new()
            .name("waterwall-dns".to_string())
            .spawn(move || {
                let mut next_event_id = 1u64;
                while let Ok(req) = request_rx.recv() {
                    let already_cached = cache_clone
                        .read()
                        .map(|c| c.contains_key(&req.ip))
                        .unwrap_or(false);
                    if already_cached {
                        continue;
                    }

                    let t0 = Instant::now();
                    let (resolved, method) = resolve_ip_hostname(req.ip);
                    let latency_ms = t0.elapsed().as_secs_f32() * 1000.0;

                    if let Ok(mut c) = cache_clone.write() {
                        c.insert(req.ip, resolved.clone());
                    }

                    let dom_label = resolved
                        .clone()
                        .unwrap_or_else(|| format!("PTR-none ({})", req.ip));
                    let proto_label = if req.protocol.is_empty() {
                        method
                    } else {
                        req.protocol
                    };

                    if let Ok(mut ev_guard) = events_clone.write() {
                        if ev_guard.len() >= MAX_DNS_EVENTS {
                            ev_guard.pop_back();
                        }
                        ev_guard.push_front(DnsEvent {
                            id: next_event_id,
                            domain: dom_label,
                            ip: req.ip,
                            app_name: req.app_name,
                            protocol: proto_label,
                            latency_ms,
                            age_secs: 0,
                            created_at: Instant::now(),
                        });
                        next_event_id += 1;
                    }
                }
            })
            .expect("failed to spawn DNS resolver thread");

        Self {
            cache,
            events,
            request_tx,
        }
    }

    pub fn get_or_resolve_for_app(
        &self,
        ip: IpAddr,
        app_name: &str,
        proto_hint: &'static str,
    ) -> Option<String> {
        if ip.is_unspecified() {
            return None;
        }
        if ip.is_loopback() {
            return Some("localhost".to_string());
        }

        if let Ok(c) = self.cache.read() {
            if let Some(cached) = c.get(&ip) {
                return cached.clone();
            }
        }

        if !is_remote_ip(&ip) {
            return Some("lan.local".to_string());
        }

        let _ = self.request_tx.send(DnsLookupReq {
            ip,
            app_name: app_name.to_string(),
            protocol: proto_hint,
        });
        None
    }

    /// Records a direct DNS socket activity event (e.g. UDP/53, DoT/853, mDNS/5353)
    pub fn record_dns_socket_query(
        &self,
        server_ip: IpAddr,
        app_name: &str,
        protocol: &'static str,
    ) {
        if let Ok(mut ev_guard) = self.events.write() {
            // Avoid spamming duplicate consecutive events from the same app + server within 5s
            if ev_guard.iter().take(8).any(|e| {
                e.ip == server_ip
                    && e.app_name.eq_ignore_ascii_case(app_name)
                    && e.created_at.elapsed().as_secs() < 5
            }) {
                return;
            }
            let id = ev_guard.front().map(|e| e.id + 1).unwrap_or(1);
            let server_dom = self
                .cache
                .read()
                .ok()
                .and_then(|c| c.get(&server_ip).cloned().flatten())
                .unwrap_or_else(|| format!("DNS Server {}", server_ip));

            if ev_guard.len() >= MAX_DNS_EVENTS {
                ev_guard.pop_back();
            }
            ev_guard.push_front(DnsEvent {
                id,
                domain: server_dom,
                ip: server_ip,
                app_name: app_name.to_string(),
                protocol,
                latency_ms: 0.4,
                age_secs: 0,
                created_at: Instant::now(),
            });
        }
    }

    pub fn events_snapshot(&self) -> Vec<DnsEvent> {
        if let Ok(guard) = self.events.read() {
            let now = Instant::now();
            guard
                .iter()
                .map(|e| {
                    let mut c = e.clone();
                    c.age_secs = now.duration_since(e.created_at).as_secs();
                    c
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn clear_events(&self) {
        if let Ok(mut guard) = self.events.write() {
            guard.clear();
        }
    }
}

fn load_etc_hosts(cache: &mut HashMap<IpAddr, Option<String>>) {
    if let Ok(content) = fs::read_to_string("/etc/hosts") {
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(ip_s), Some(host)) = (parts.next(), parts.next()) {
                if let Ok(ip) = ip_s.parse::<IpAddr>() {
                    if !ip.is_loopback() {
                        cache.insert(ip, Some(host.to_string()));
                    }
                }
            }
        }
    }
}

/// Multi-stage Linux hostname resolution:
/// 1. `getent hosts <ip>` (queries NSS including `systemd-resolved` and `mdns`)
/// 2. `libc::getnameinfo(..., NI_NAMEREQD)`
fn resolve_ip_hostname(ip: IpAddr) -> (Option<String>, &'static str) {
    // Stage 1: Fast NSS / systemd-resolved cache lookup via `getent hosts`
    if let Ok(out) = Command::new("getent")
        .arg("hosts")
        .arg(ip.to_string())
        .output()
    {
        if out.status.success() {
            if let Ok(stdout) = String::from_utf8(out.stdout) {
                if let Some(host) = stdout.split_whitespace().nth(1) {
                    let clean = host.trim_end_matches('.').to_string();
                    if !clean.is_empty() && clean != ip.to_string() {
                        return (Some(clean), "NSS/Resolved");
                    }
                }
            }
        }
    }

    // Stage 2: POSIX getnameinfo reverse PTR lookup
    if let Some(ptr) = resolve_rdns_libc(ip) {
        return (Some(ptr), "rDNS PTR");
    }

    (None, "Unresolved")
}

fn resolve_rdns_libc(ip: IpAddr) -> Option<String> {
    unsafe {
        let mut host_buf = [0u8; 256];
        let res = match ip {
            IpAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                libc::getnameinfo(
                    &sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let sin6 = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                libc::getnameinfo(
                    &sin6 as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr() as *mut libc::c_char,
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        };

        if res == 0 {
            let len = host_buf.iter().position(|&c| c == 0).unwrap_or(0);
            if len > 0 {
                let s = String::from_utf8_lossy(&host_buf[..len]).to_string();
                if s != ip.to_string() {
                    return Some(s);
                }
            }
        }
    }
    None
}
