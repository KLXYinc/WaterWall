use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::ebpf_redirect::{resolve_pids_for_app_names, sync_ebpf_proxied_pids};
use super::killer;
use super::proxy_relay::{LocalProxyRelay, UpstreamProxyConfig, UpstreamProxyKind};
use crate::gui::nodes::pin_id;
use crate::utils::graph_save_candidates;

pub const PRIMARY_SOCK_PATH: &str = "/run/waterwall.sock";
pub const FALLBACK_SOCK_PATH: &str = "/tmp/waterwall.sock";

pub fn get_socket_path() -> PathBuf {
    if Path::new("/run").is_dir() && unsafe { libc::geteuid() } == 0 {
        PathBuf::from(PRIMARY_SOCK_PATH)
    } else {
        PathBuf::from(FALLBACK_SOCK_PATH)
    }
}

/// Send a command to the running background WaterWall daemon
pub fn send_daemon_command(cmd: &str) -> Option<String> {
    let sock_paths = [PRIMARY_SOCK_PATH, FALLBACK_SOCK_PATH];
    for path in sock_paths {
        if let Ok(mut stream) = UnixStream::connect(path) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
            if writeln!(stream, "{}", cmd).is_ok() {
                let mut reader = BufReader::new(stream);
                let mut response = String::new();
                if reader.read_line(&mut response).is_ok() {
                    return Some(response.trim().to_string());
                }
            }
        }
    }
    None
}

/// Start the background daemon IPC server and attach the eBPF cgroup/connect4+6 hooks
pub fn run_daemon_server(running: Arc<AtomicBool>) -> std::io::Result<()> {
    let sock_path = get_socket_path();
    if sock_path.exists() {
        let _ = fs::remove_file(&sock_path);
    }

    let relay = Arc::new(LocalProxyRelay::new());
    let (initial_pids, initial_cfg) = scan_saved_config_proxied_state();
    if let Some(cfg) = initial_cfg {
        relay.update_config(cfg);
    }
    let (ebpf_ok, ebpf_msg) = sync_ebpf_proxied_pids(&initial_pids);
    println!("WaterWall eBPF Redirector: {} ({})", ebpf_msg, ebpf_ok);

    let listener = UnixListener::bind(&sock_path)?;
    let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o666));
    listener.set_nonblocking(true)?;

    println!("WaterWall Daemon listening on unix:{}", sock_path.display());

    let mut last_cfg_sync = Instant::now();
    let mut prev_hooked_count = initial_pids.len();

    while running.load(Ordering::SeqCst) {
        if last_cfg_sync.elapsed() >= Duration::from_millis(1200) {
            last_cfg_sync = Instant::now();
            let (cfg_pids, cfg_proxy) = scan_saved_config_proxied_state();
            if let Some(cfg) = cfg_proxy {
                relay.update_config(cfg);
            }
            if !cfg_pids.is_empty() || prev_hooked_count > 0 {
                let (_, msg) = sync_ebpf_proxied_pids(&cfg_pids);
                if cfg_pids.len() != prev_hooked_count {
                    println!("WaterWall Daemon: {} -> PIDs {:?}", msg, cfg_pids);
                    prev_hooked_count = cfg_pids.len();
                }
            }
        }

        match listener.accept() {
            Ok((stream, _)) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("Daemon listener error: {}", e);
                break;
            }
        }
    }

    if sock_path.exists() {
        let _ = fs::remove_file(&sock_path);
    }
    Ok(())
}

/// Reads saved `flow_graph.cfg` files across user config directories
/// so the root daemon automatically hooks proxied apps and loads proxy credentials.
pub fn scan_saved_config_proxied_state() -> (Vec<u32>, Option<UpstreamProxyConfig>) {
    for path in graph_save_candidates() {
        if let Ok(content) = fs::read_to_string(&path) {
            let mut proxy_node_ids: HashSet<i32> = HashSet::new();
            let mut group_node_to_gid: Vec<(i32, usize)> = Vec::new();
            let mut links: Vec<(i32, i32)> = Vec::new();
            let mut app_assigns: Vec<(String, usize)> = Vec::new();
            let mut proxy_type = UpstreamProxyKind::HttpConnect;
            let mut proxy_srv = String::new();
            let mut proxy_usr = String::new();
            let mut proxy_pwd = String::new();

            for line in content.lines() {
                let parts: Vec<&str> = line.trim().split('|').collect();
                match parts.first().copied().unwrap_or("") {
                    "ASSIGN" if parts.len() >= 3 => {
                        if let Ok(gid) = parts[2].parse::<usize>() {
                            app_assigns.push((parts[1].to_string(), gid));
                        }
                    }
                    "NODE" if parts.len() >= 6 => {
                        if let Ok(nid) = parts[1].parse::<i32>() {
                            if parts[2] == "ProxyNode" {
                                proxy_node_ids.insert(nid);
                            } else if parts[2] == "AppGroup" {
                                if let Ok(gid) = parts[5].parse::<usize>() {
                                    group_node_to_gid.push((nid, gid));
                                }
                            }
                        }
                    }
                    "ITEM_CMB" if parts.len() >= 4 => {
                        if let Ok(nid) = parts[1].parse::<i32>() {
                            if proxy_node_ids.contains(&nid) && parts[2] == "Type:" {
                                proxy_type = if parts[3] == "1" {
                                    UpstreamProxyKind::HttpConnect
                                } else {
                                    UpstreamProxyKind::Socks5
                                };
                            }
                        }
                    }
                    "ITEM_TXT" if parts.len() >= 4 => {
                        if let Ok(nid) = parts[1].parse::<i32>() {
                            if proxy_node_ids.contains(&nid) {
                                match parts[2] {
                                    "Server:" => proxy_srv = parts[3].to_string(),
                                    "User:" => proxy_usr = parts[3].to_string(),
                                    "Pass:" => proxy_pwd = parts[3].to_string(),
                                    _ => {}
                                }
                            }
                        }
                    }
                    "LINK" if parts.len() >= 4 => {
                        if let (Ok(from), Ok(to)) = (parts[2].parse::<i32>(), parts[3].parse::<i32>()) {
                            links.push((from, to));
                        }
                    }
                    _ => {}
                }
            }

            if proxy_node_ids.is_empty() {
                continue;
            }

            let mut proxied_gids: HashSet<usize> = HashSet::new();
            for &(gnid, gid) in &group_node_to_gid {
                let mut cur_out_pin = pin_id(gnid, 1);
                for _ in 0..5 {
                    let Some(&(_, to_pin)) = links.iter().find(|&&(f, _)| f == cur_out_pin) else {
                        break;
                    };
                    let next_nid = to_pin / 100;
                    if proxy_node_ids.contains(&next_nid) {
                        proxied_gids.insert(gid);
                        break;
                    }
                    cur_out_pin = pin_id(next_nid, 2);
                }
            }

            if !proxied_gids.is_empty() {
                let app_names: Vec<String> = app_assigns
                    .into_iter()
                    .filter(|(_, gid)| proxied_gids.contains(gid))
                    .map(|(name, _)| name)
                    .collect();
                let cfg = (!proxy_srv.is_empty()).then_some(UpstreamProxyConfig {
                    enabled: true,
                    kind: proxy_type,
                    server: proxy_srv,
                    username: proxy_usr,
                    password: proxy_pwd,
                });
                return (resolve_pids_for_app_names(&app_names, &[]), cfg);
            }
        }
    }
    (Vec::new(), None)
}

fn handle_client(mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let reader = BufReader::new(cloned);

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cmd = parts[0].to_uppercase();

        match cmd.as_str() {
            "PING" => {
                let _ = writeln!(stream, "PONG");
            }
            "STATUS" => {
                let _ = writeln!(stream, "OK daemon=active");
            }
            "EBPF_PIDS" => {
                let pids: Vec<u32> = parts
                    .get(1)
                    .copied()
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect();
                let (ok, msg) = sync_ebpf_proxied_pids(&pids);
                let _ = writeln!(stream, "OK ebpf={} {}", ok, msg);
            }
            "BLOCK" if parts.len() > 1 => {
                let pids: Vec<u32> = parts[1]
                    .split(',')
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
                let _ = writeln!(stream, "OK blocked={:?}", pids);
            }
            "UNBLOCK" if parts.len() > 1 => {
                let pids: Vec<u32> = parts[1]
                    .split(',')
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
                let _ = writeln!(stream, "OK unblocked={:?}", pids);
            }
            "KILL" if parts.len() > 1 => {
                if let Ok(addr) = parts[1].parse::<std::net::SocketAddr>() {
                    let killed = killer::terminate_single_socket(&addr);
                    let _ = writeln!(stream, "OK killed={}", killed);
                } else {
                    let _ = writeln!(stream, "ERR invalid_socket_address");
                }
            }
            _ => {
                let _ = writeln!(stream, "ERR unknown_command");
            }
        }
    }
}
