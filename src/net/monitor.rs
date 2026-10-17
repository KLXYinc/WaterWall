use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use super::dns::DnsResolver;
use super::ebpf_redirect::unmap_ebpf_addr;
use super::proxy_relay::{LocalProxyRelay, LOCAL_RELAY_PORT};
use super::records::{
    HostRecord, NetworkSnapshot, PersistentSessionState, ProtocolRecord, SecurityAlert, HISTORY_LEN,
};
use super::scanner::{
    read_system_net_dev, scan_all_sockets, scan_process_metadata, scan_vpn_interfaces, ProcSocket,
};
use super::socket::{is_remote_ip, AppNetworkInfo, ConnectionInfo, Protocol};

pub struct NetworkMonitor {
    snapshot: Arc<RwLock<NetworkSnapshot>>,
    paused_snapshot: Arc<RwLock<Option<NetworkSnapshot>>>,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    incognito: Arc<AtomicBool>,
    clear_requested: Arc<AtomicBool>,
    pub dns: DnsResolver,
    pub proxy_relay: Arc<LocalProxyRelay>,
    blocked_pids: Arc<RwLock<HashMap<u32, bool>>>,
    proxied_pids: Arc<RwLock<HashMap<u32, bool>>>,
    blocked_names: Arc<RwLock<HashMap<String, bool>>>,
    proxied_names: Arc<RwLock<HashMap<String, bool>>>,
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let snapshot = Arc::new(RwLock::new(NetworkSnapshot::default()));
        let paused_snapshot = Arc::new(RwLock::new(None));
        let running = Arc::new(AtomicBool::new(true));
        let paused = Arc::new(AtomicBool::new(false));
        let incognito = Arc::new(AtomicBool::new(false));
        let clear_requested = Arc::new(AtomicBool::new(false));
        let dns = DnsResolver::new();
        let proxy_relay = Arc::new(LocalProxyRelay::new());
        let blocked_pids = Arc::new(RwLock::new(HashMap::new()));
        let proxied_pids = Arc::new(RwLock::new(HashMap::new()));
        let blocked_names = Arc::new(RwLock::new(HashMap::new()));
        let proxied_names = Arc::new(RwLock::new(HashMap::new()));

        let snapshot_clone = Arc::clone(&snapshot);
        let running_clone = Arc::clone(&running);
        let incognito_clone = Arc::clone(&incognito);
        let clear_clone = Arc::clone(&clear_requested);
        let dns_clone = dns.clone();
        let blocked_clone = Arc::clone(&blocked_pids);
        let proxied_clone = Arc::clone(&proxied_pids);
        let blocked_names_clone = Arc::clone(&blocked_names);
        let proxied_names_clone = Arc::clone(&proxied_names);

        thread::Builder::new()
            .name("waterwall-monitor".to_string())
            .spawn(move || {
                let mut prev_time = Instant::now();
                let mut prev_proc_io: HashMap<u32, (u64, u64)> = HashMap::new();
                let mut prev_sys_net = read_system_net_dev();
                let mut total_session_down = 0u64;
                let mut total_session_up = 0u64;
                let mut down_history: Vec<f32> = vec![0.0; HISTORY_LEN];
                let mut up_history: Vec<f32> = vec![0.0; HISTORY_LEN];
                let mut state = PersistentSessionState::default();

                while running_clone.load(Ordering::Relaxed) {
                    if clear_clone.swap(false, Ordering::Relaxed) {
                        total_session_down = 0;
                        total_session_up = 0;
                        down_history.fill(0.0);
                        up_history.fill(0.0);
                        state = PersistentSessionState::default();
                        dns_clone.clear_events();
                    }

                    let is_incog = incognito_clone.load(Ordering::Relaxed);
                    let now = Instant::now();
                    let dt = now.duration_since(prev_time).as_secs_f64().max(0.1);
                    prev_time = now;

                    let current_sys_net = read_system_net_dev();
                    let sys_rx_delta = current_sys_net.rx_bytes.saturating_sub(prev_sys_net.rx_bytes);
                    let sys_tx_delta = current_sys_net.tx_bytes.saturating_sub(prev_sys_net.tx_bytes);
                    prev_sys_net = current_sys_net;

                    let system_down_speed = (sys_rx_delta as f64 / dt).max(0.0);
                    let system_up_speed = (sys_tx_delta as f64 / dt).max(0.0);
                    if !is_incog {
                        total_session_down = total_session_down.saturating_add(sys_rx_delta);
                        total_session_up = total_session_up.saturating_add(sys_tx_delta);
                    }

                    down_history.remove(0);
                    down_history.push(system_down_speed as f32);
                    up_history.remove(0);
                    up_history.push(system_up_speed as f32);

                    let raw_sockets = scan_all_sockets();
                    let mut inode_to_sockets: HashMap<u64, Vec<ProcSocket>> = HashMap::new();
                    for s in raw_sockets {
                        inode_to_sockets.entry(s.inode).or_default().push(s);
                    }

                    let procs = scan_process_metadata();
                    let mut grouped_map: HashMap<String, AppNetworkInfo> = HashMap::new();

                    for (pid, meta) in &procs {
                        let mut conns = Vec::new();
                        for inode in &meta.inodes {
                            if let Some(sockets) = inode_to_sockets.get(inode) {
                                for s in sockets {
                                    let lport = s.local_addr.port();
                                    if lport == LOCAL_RELAY_PORT {
                                        continue;
                                    }

                                    // Unmap eBPF-redirected sockets (127.100.<lo>.<hi>:19180) back to their real remote WAN destination!
                                    let mut remote_addr = s.remote_addr;
                                    if remote_addr.port() == LOCAL_RELAY_PORT {
                                        if let Some(orig) = unmap_ebpf_addr(remote_addr) {
                                            remote_addr = orig;
                                        }
                                    }
                                    let rport = remote_addr.port();

                                    // Detect direct DNS / DoT / mDNS socket activity
                                    if !is_incog && matches!(rport, 53 | 853 | 5353) && !remote_addr.ip().is_unspecified() {
                                        let dns_proto = match (rport, s.protocol) {
                                            (853, _) => "DoT/853",
                                            (5353, _) => "mDNS/5353",
                                            (53, Protocol::Tcp) => "TCP/53",
                                            _ => "UDP/53",
                                        };
                                        dns_clone.record_dns_socket_query(
                                            remote_addr.ip(),
                                            &meta.name,
                                            dns_proto,
                                        );
                                    }

                                    let domain = if rport != 0 && !remote_addr.ip().is_unspecified() {
                                        dns_clone.get_or_resolve_for_app(
                                            remote_addr.ip(),
                                            &meta.name,
                                            if lport == 5353 || rport == 5353 { "mDNS" } else { "" },
                                        )
                                    } else {
                                        None
                                    };
                                    conns.push(ConnectionInfo {
                                        protocol: s.protocol,
                                        local_addr: s.local_addr,
                                        remote_addr,
                                        state: s.state,
                                        inode: s.inode,
                                        domain,
                                    });
                                }
                            }
                        }

                        if conns.is_empty() {
                            continue;
                        }

                        let (prev_r, prev_w) = prev_proc_io
                            .get(pid)
                            .copied()
                            .unwrap_or((meta.rchar, meta.wchar));
                        let down_delta = meta.rchar.saturating_sub(prev_r);
                        let up_delta = meta.wchar.saturating_sub(prev_w);
                        prev_proc_io.insert(*pid, (meta.rchar, meta.wchar));

                        let download_speed = (down_delta as f64 / dt).max(0.0);
                        let upload_speed = (up_delta as f64 / dt).max(0.0);
                        let name_key = meta.name.to_lowercase();

                        let is_blocked = blocked_clone
                            .read()
                            .map(|b| b.get(pid).copied().unwrap_or(false))
                            .unwrap_or(false)
                            || blocked_names_clone
                                .read()
                                .map(|b| b.get(&name_key).copied().unwrap_or(false))
                                .unwrap_or(false);

                        let is_proxied = proxied_clone
                            .read()
                            .map(|p| p.get(pid).copied().unwrap_or(false))
                            .unwrap_or(false)
                            || proxied_names_clone
                                .read()
                                .map(|p| p.get(&name_key).copied().unwrap_or(false))
                                .unwrap_or(false);

                        if let Some(existing) = grouped_map.get_mut(&name_key) {
                            existing.instance_count += 1;
                            existing.pids.push(*pid);
                            existing.upload_speed += upload_speed;
                            existing.download_speed += download_speed;
                            existing.total_uploaded += meta.wchar;
                            existing.total_downloaded += meta.rchar;
                            existing.is_blocked |= is_blocked;
                            existing.is_proxied |= is_proxied;
                            for c in conns {
                                if !existing
                                    .connections
                                    .iter()
                                    .any(|ec| ec.inode == c.inode && ec.local_addr == c.local_addr)
                                {
                                    existing.connections.push(c);
                                }
                            }
                        } else {
                            grouped_map.insert(
                                name_key,
                                AppNetworkInfo {
                                    pid: *pid,
                                    instance_count: 1,
                                    pids: vec![*pid],
                                    name: meta.name.clone(),
                                    exe_path: meta.exe_path.clone(),
                                    cmdline: meta.cmdline.clone(),
                                    connections: conns,
                                    upload_speed,
                                    download_speed,
                                    total_uploaded: meta.wchar,
                                    total_downloaded: meta.rchar,
                                    download_history: Vec::new(),
                                    upload_history: Vec::new(),
                                    first_seen_id: 0,
                                    is_blocked,
                                    is_proxied,
                                },
                            );
                        }
                    }

                    state.reset_socket_counters();

                    let mut final_app_list: Vec<AppNetworkInfo> = grouped_map
                        .into_values()
                        .map(|app| state.update_app_and_endpoints(app, dt, is_incog))
                        .collect();

                    final_app_list.sort_by(|a, b| {
                        let ta = a.total_downloaded + a.total_uploaded;
                        let tb = b.total_downloaded + b.total_uploaded;
                        tb.cmp(&ta).then_with(|| a.first_seen_id.cmp(&b.first_seen_id))
                    });

                    let mut hosts_vec: Vec<HostRecord> = state.hosts.values().cloned().collect();
                    hosts_vec.sort_by_key(|a| a.first_seen_id);

                    let mut protos_vec: Vec<ProtocolRecord> =
                        state.protocols.values().cloned().collect();
                    protos_vec.sort_by_key(|a| a.first_seen_id);

                    let alerts_vec: Vec<SecurityAlert> = state
                        .alerts
                        .iter()
                        .map(|a| {
                            let mut c = a.clone();
                            c.age_secs = now.duration_since(a.created_at).as_secs();
                            c
                        })
                        .collect();

                    let vpn_ifaces = scan_vpn_interfaces();
                    let dns_events = dns_clone.events_snapshot();

                    prev_proc_io.retain(|pid, _| procs.contains_key(pid));

                    let total_active_conns = final_app_list
                        .iter()
                        .map(|a| a.active_connection_count())
                        .sum();
                    let total_sockets = final_app_list
                        .iter()
                        .map(|a| a.total_connection_count())
                        .sum();

                    if let Ok(mut snap) = snapshot_clone.write() {
                        snap.apps = final_app_list;
                        snap.hosts = hosts_vec;
                        snap.protocols = protos_vec;
                        snap.dns_events = dns_events;
                        snap.alerts = alerts_vec;
                        snap.vpn_interfaces = vpn_ifaces;
                        snap.system_download_speed = system_down_speed;
                        snap.system_upload_speed = system_up_speed;
                        snap.session_total_download = total_session_down;
                        snap.session_total_upload = total_session_up;
                        snap.session_wan_bytes = state.session_wan_bytes.max(total_session_down);
                        snap.session_lan_bytes = state.session_lan_bytes;
                        snap.total_active_connections = total_active_conns;
                        snap.total_sockets_count = total_sockets;
                        snap.download_history = down_history.clone();
                        snap.upload_history = up_history.clone();
                        snap.last_updated = Some(now);
                    }

                    thread::sleep(Duration::from_millis(800));
                }
            })
            .expect("failed to spawn network monitor thread");

        Self {
            snapshot,
            paused_snapshot,
            running,
            paused,
            incognito,
            clear_requested,
            dns,
            proxy_relay,
            blocked_pids,
            proxied_pids,
            blocked_names,
            proxied_names,
        }
    }

    pub fn snapshot(&self) -> NetworkSnapshot {
        if self.is_paused() {
            if let Ok(guard) = self.paused_snapshot.read() {
                if let Some(frozen) = &*guard {
                    return frozen.clone();
                }
            }
        }
        self.snapshot.read().unwrap().clone()
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn toggle_pause(&self) -> bool {
        let now_paused = !self.is_paused();
        if now_paused {
            let current = self.snapshot.read().unwrap().clone();
            if let Ok(mut guard) = self.paused_snapshot.write() {
                *guard = Some(current);
            }
        } else if let Ok(mut guard) = self.paused_snapshot.write() {
            *guard = None;
        }
        self.paused.store(now_paused, Ordering::Relaxed);
        now_paused
    }

    pub fn is_incognito(&self) -> bool {
        self.incognito.load(Ordering::Relaxed)
    }

    pub fn toggle_incognito(&self) -> bool {
        let next = !self.is_incognito();
        self.incognito.store(next, Ordering::Relaxed);
        next
    }

    pub fn clear_history(&self) {
        self.clear_requested.store(true, Ordering::Relaxed);
    }

    pub fn set_app_blocked_by_name(&self, app_name: &str, blocked: bool) {
        let key = app_name.to_lowercase();
        let current = self
            .blocked_names
            .read()
            .map(|b| b.get(&key).copied().unwrap_or(false))
            .unwrap_or(false);
        if current == blocked {
            return;
        }
        if let Ok(mut bn) = self.blocked_names.write() {
            bn.insert(key, blocked);
        }
        if let Ok(snap) = self.snapshot.read() {
            for app in &snap.apps {
                if app.name.eq_ignore_ascii_case(app_name) {
                    if let Ok(mut bp) = self.blocked_pids.write() {
                        for &p in &app.pids {
                            bp.insert(p, blocked);
                        }
                    }
                    if blocked {
                        super::killer::terminate_sockets(&app.connections);
                    }
                }
            }
        }
    }

    pub fn set_app_proxied_by_name(&self, app_name: &str, proxied: bool) {
        let key = app_name.to_lowercase();
        let current = self
            .proxied_names
            .read()
            .map(|p| p.get(&key).copied().unwrap_or(false))
            .unwrap_or(false);
        if current == proxied {
            return;
        }
        if let Ok(mut pn) = self.proxied_names.write() {
            pn.insert(key, proxied);
        }
        if let Ok(snap) = self.snapshot.read() {
            for app in &snap.apps {
                if app.name.eq_ignore_ascii_case(app_name) {
                    if let Ok(mut pp) = self.proxied_pids.write() {
                        for &p in &app.pids {
                            pp.insert(p, proxied);
                        }
                    }
                    // When an app transitions to proxied, drop its old direct WAN sockets once
                    // so keep-alive connections immediately reconnect through the eBPF proxy hook!
                    if proxied {
                        for conn in &app.connections {
                            if conn.remote_addr.port() != 0 && is_remote_ip(&conn.remote_addr.ip())
                            {
                                super::killer::terminate_single_socket(&conn.remote_addr);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}
