use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::proxy_relay::LOCAL_RELAY_PORT;
use crate::utils::{
    bpf_attach_cgroup, bpf_create_slot_map, bpf_load_connect4_prog, bpf_load_connect6_prog,
    bpf_lookup_u64_elem, bpf_obj_get_map, bpf_pin_map, BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
};

const PROXY_CGROUP_DIR: &str = "/sys/fs/cgroup/waterwall_proxy";
const DIRECT_CGROUP_DIR: &str = "/sys/fs/cgroup/waterwall_direct";

static GLOBAL_SLOT_MAP_FD: AtomicI32 = AtomicI32::new(-1);

/// Looks up the original destination `(Ipv4Addr, u16)` stored by the eBPF `cgroup/connect4` hook at `slot`.
pub fn lookup_orig_dst_slot(slot: u32) -> Option<SocketAddrV4> {
    let mut map_fd = GLOBAL_SLOT_MAP_FD.load(Ordering::Relaxed);
    if map_fd < 0 {
        map_fd = bpf_obj_get_map();
        if map_fd >= 0 {
            GLOBAL_SLOT_MAP_FD.store(map_fd, Ordering::Relaxed);
        }
    }
    if map_fd < 0 {
        return None;
    }

    let val = bpf_lookup_u64_elem(map_fd, slot)?;
    let ip = Ipv4Addr::from(u32::from_be((val & 0xFFFF_FFFF) as u32));
    let port = u16::from_be(((val >> 32) & 0xFFFF) as u16);
    (port != 0).then(|| SocketAddrV4::new(ip, port))
}

/// If `addr` is an eBPF-redirected loopback slot (`127.100.<lo>.<hi>`), resolves its original WAN destination.
pub fn unmap_ebpf_addr(addr: SocketAddr) -> Option<SocketAddr> {
    let v4 = match addr.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => v6.to_ipv4_mapped()?,
    };
    let oct = v4.octets();
    if oct[0] == 127 && oct[1] == 100 {
        let slot = (oct[2] as u32) | ((oct[3] as u32) << 8);
        lookup_orig_dst_slot(slot).map(SocketAddr::V4)
    } else {
        None
    }
}

/// Scans `/proc` for all PIDs matching any application name in `app_names` (matching `comm` or `/proc/[pid]/exe` file stem).
pub fn resolve_pids_for_app_names(app_names: &[String], seed_pids: &[u32]) -> Vec<u32> {
    let mut pids: HashSet<u32> = seed_pids.iter().copied().filter(|&p| p > 1).collect();
    if app_names.is_empty() {
        return pids.into_iter().collect();
    }

    let lower_names: Vec<String> = app_names.iter().map(|s| s.to_lowercase()).collect();
    let self_pid = std::process::id();

    if let Ok(proc_dir) = fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if pid <= 1 || pid == self_pid {
                continue;
            }
            let pid_path = entry.path();
            let comm = fs::read_to_string(pid_path.join("comm"))
                .map(|s| s.trim().to_lowercase())
                .unwrap_or_default();
            let exe = fs::read_link(pid_path.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            if lower_names.iter().any(|t| {
                comm == *t
                    || exe == *t
                    || (!exe.is_empty() && (exe.starts_with(t) || t.starts_with(&exe)))
            }) {
                pids.insert(pid);
            }
        }
    }

    let mut out: Vec<u32> = pids.into_iter().collect();
    out.sort_unstable();
    out
}

pub struct EbpfRedirector {
    attached: bool,
    status: String,
    proxied_pids: HashSet<u32>,
    elevation_requested: bool,
    last_sync_at: Option<Instant>,
    last_app_key: Vec<String>,
}

static REDIRECTOR: Mutex<Option<EbpfRedirector>> = Mutex::new(None);

pub fn sync_ebpf_proxied_pids(target_pids: &[u32]) -> (bool, String) {
    let mut guard = REDIRECTOR.lock().unwrap();
    let redir = guard.get_or_insert_with(EbpfRedirector::new);
    redir.sync_pids(target_pids)
}

/// Throttled helper for the UI loop: resolves PIDs for `app_names` and syncs eBPF cgroups at most once per second
/// unless the target app list changed.
pub fn sync_ebpf_for_apps(app_names: &[String], seed_pids: &[u32]) -> (bool, String) {
    let mut key: Vec<String> = app_names.iter().map(|s| s.to_lowercase()).collect();
    key.sort_unstable();
    key.dedup();

    let mut guard = REDIRECTOR.lock().unwrap();
    let redir = guard.get_or_insert_with(EbpfRedirector::new);

    let now = Instant::now();
    let recently_synced = redir
        .last_sync_at
        .is_some_and(|t| now.duration_since(t) < Duration::from_millis(1000));
    if recently_synced && redir.last_app_key == key {
        return (
            redir.attached || !redir.proxied_pids.is_empty(),
            redir.status.clone(),
        );
    }

    redir.last_sync_at = Some(now);
    redir.last_app_key = key;
    drop(guard);

    let resolved = resolve_pids_for_app_names(app_names, seed_pids);
    sync_ebpf_proxied_pids(&resolved)
}

pub fn request_ebpf_elevation() -> String {
    if let Ok(mut guard) = REDIRECTOR.lock() {
        return guard
            .get_or_insert_with(EbpfRedirector::new)
            .spawn_pkexec_helper();
    }
    String::from("Failed to lock eBPF redirector")
}

impl EbpfRedirector {
    fn new() -> Self {
        let mut s = Self {
            attached: false,
            status: String::from("eBPF Standby"),
            proxied_pids: HashSet::new(),
            elevation_requested: false,
            last_sync_at: None,
            last_app_key: Vec::new(),
        };
        s.try_init_in_process();
        s
    }

    fn try_init_in_process(&mut self) {
        if unsafe { libc::geteuid() } != 0 {
            self.status = String::from("Need Root Helper for eBPF Hook");
            return;
        }

        let _ = fs::create_dir_all(PROXY_CGROUP_DIR);
        let _ = fs::create_dir_all(DIRECT_CGROUP_DIR);

        let map_fd = match bpf_create_slot_map() {
            Ok(fd) => fd,
            Err(e) => {
                self.status = format!("eBPF map error: {}", e);
                return;
            }
        };
        GLOBAL_SLOT_MAP_FD.store(map_fd, Ordering::Relaxed);
        let _ = bpf_pin_map(map_fd);

        let prog4_fd = match bpf_load_connect4_prog(map_fd, LOCAL_RELAY_PORT) {
            Ok(fd) => fd,
            Err(e) => {
                self.status = format!("eBPF connect4 error: {}", e);
                return;
            }
        };

        let Ok(cg_file) = fs::File::open(PROXY_CGROUP_DIR) else {
            self.status = String::from("Failed to open /sys/fs/cgroup/waterwall_proxy");
            return;
        };

        if let Err(e) = bpf_attach_cgroup(cg_file.as_raw_fd(), prog4_fd, BPF_CGROUP_INET4_CONNECT) {
            self.status = format!("eBPF attach4 error: {}", e);
            return;
        }

        if let Ok(prog6_fd) = bpf_load_connect6_prog(LOCAL_RELAY_PORT) {
            let _ = bpf_attach_cgroup(cg_file.as_raw_fd(), prog6_fd, BPF_CGROUP_INET6_CONNECT);
        }

        self.attached = true;
        self.status = String::from("eBPF cgroup/connect4+6 ACTIVE");
    }

    fn sync_pids(&mut self, target_pids: &[u32]) -> (bool, String) {
        let self_pid = std::process::id();
        let desired: HashSet<u32> = target_pids
            .iter()
            .copied()
            .filter(|&p| p > 1 && p != self_pid)
            .collect();

        if unsafe { libc::geteuid() } == 0 {
            if !self.attached {
                self.try_init_in_process();
            }
            if self.attached {
                if self.proxied_pids != desired {
                    for &pid in &desired {
                        let _ =
                            fs::write(format!("{}/cgroup.procs", PROXY_CGROUP_DIR), pid.to_string());
                    }
                    for &old_pid in &self.proxied_pids {
                        if !desired.contains(&old_pid) {
                            let _ = fs::write(
                                format!("{}/cgroup.procs", DIRECT_CGROUP_DIR),
                                old_pid.to_string(),
                            );
                        }
                    }
                    self.proxied_pids = desired;
                }
                self.status = format!("eBPF ACTIVE ({} PIDs hooked)", self.proxied_pids.len());
                return (true, self.status.clone());
            }
        }

        if Path::new("/sys/fs/bpf/waterwall_slots").exists() {
            if self.proxied_pids == desired && !desired.is_empty() {
                self.status = format!("eBPF ACTIVE ({} PIDs hooked)", self.proxied_pids.len());
                return (true, self.status.clone());
            }
            let mut sorted: Vec<u32> = desired.iter().copied().collect();
            sorted.sort_unstable();
            let csv = sorted
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            if let Some(resp) = super::ipc::send_daemon_command(&format!("EBPF_PIDS {}", csv)) {
                if resp.starts_with("OK") {
                    self.proxied_pids = desired;
                    self.status = format!("eBPF ACTIVE ({} PIDs hooked)", self.proxied_pids.len());
                    return (true, self.status.clone());
                }
            }
        }

        if !desired.is_empty() && !self.elevation_requested {
            self.elevation_requested = true;
            let _ = self.spawn_pkexec_helper();
        }

        self.status = String::from("Restart 'sudo waterwall --daemon' or click Enable eBPF Hook");
        (false, self.status.clone())
    }

    fn spawn_pkexec_helper(&mut self) -> String {
        self.elevation_requested = true;
        let exe = std::env::current_exe().unwrap_or_else(|_| "target/debug/waterwall".into());
        match Command::new("pkexec").arg(exe).arg("--daemon").spawn() {
            Ok(_) => {
                self.status = String::from("Waiting for pkexec root approval...");
                self.status.clone()
            }
            Err(e) => {
                self.status = format!("Run: sudo waterwall --daemon ({})", e);
                self.status.clone()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_proxied_pids_from_saved_config() {
        let (pids, _) = super::super::ipc::scan_saved_config_proxied_state();
        println!("Resolved proxied PIDs from flow_graph.cfg: {:?}", pids);
        let lw_pids = resolve_pids_for_app_names(&["librewolf".to_string()], &[]);
        println!("Resolved librewolf PIDs: {:?}", lw_pids);
    }
}
