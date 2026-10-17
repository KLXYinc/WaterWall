use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use super::proxy_relay::LOCAL_RELAY_PORT;

const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_OBJ_PIN: libc::c_long = 6;
const BPF_OBJ_GET: libc::c_long = 7;
const BPF_PROG_ATTACH: libc::c_long = 8;

const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const BPF_CGROUP_INET4_CONNECT: u32 = 10;
const BPF_CGROUP_INET6_CONNECT: u32 = 11;
const BPF_F_ALLOW_OVERRIDE: u32 = 1;

const PINNED_SLOT_MAP_PATH: &str = "/sys/fs/bpf/waterwall_slots\0";
const PROXY_CGROUP_DIR: &str = "/sys/fs/cgroup/waterwall_proxy";
const DIRECT_CGROUP_DIR: &str = "/sys/fs/cgroup/waterwall_direct";

static GLOBAL_SLOT_MAP_FD: AtomicI32 = AtomicI32::new(-1);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self { code, regs: (dst & 0x0F) | ((src & 0x0F) << 4), off, imm }
    }
}

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

    let key: u32 = slot;
    let mut val: u64 = 0;

    #[repr(C)]
    struct MapElemAttr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: &key as *const u32 as u64,
        value: &mut val as *mut u64 as u64,
        flags: 0,
    };

    let ret = unsafe {
        libc::syscall(libc::SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr as *const MapElemAttr, std::mem::size_of::<MapElemAttr>())
    };
    if ret != 0 || val == 0 {
        return None;
    }

    let ip = Ipv4Addr::from(u32::from_be((val & 0xFFFF_FFFF) as u32));
    let port = u16::from_be(((val >> 32) & 0xFFFF) as u16);
    (port != 0).then(|| SocketAddrV4::new(ip, port))
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
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            if pid <= 1 || pid == self_pid {
                continue;
            }
            let pid_path = entry.path();
            let comm = fs::read_to_string(pid_path.join("comm")).map(|s| s.trim().to_lowercase()).unwrap_or_default();
            let exe = fs::read_link(pid_path.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_lowercase()))
                .unwrap_or_default();

            if lower_names.iter().any(|t| comm == *t || exe == *t || (!exe.is_empty() && (exe.starts_with(t) || t.starts_with(&exe)))) {
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
}

static REDIRECTOR: Mutex<Option<EbpfRedirector>> = Mutex::new(None);

pub fn sync_ebpf_proxied_pids(target_pids: &[u32]) -> (bool, String) {
    let mut guard = REDIRECTOR.lock().unwrap();
    let redir = guard.get_or_insert_with(EbpfRedirector::new);
    redir.sync_pids(target_pids)
}

pub fn request_ebpf_elevation() -> String {
    if let Ok(mut guard) = REDIRECTOR.lock() {
        return guard.get_or_insert_with(EbpfRedirector::new).spawn_pkexec_helper();
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
        let desired: HashSet<u32> = target_pids.iter().copied().filter(|&p| p > 1 && p != self_pid).collect();

        if unsafe { libc::geteuid() } == 0 {
            if !self.attached {
                self.try_init_in_process();
            }
            if self.attached {
                for &pid in &desired {
                    let _ = fs::write(format!("{}/cgroup.procs", PROXY_CGROUP_DIR), pid.to_string());
                }
                for &old_pid in &self.proxied_pids {
                    if !desired.contains(&old_pid) {
                        let _ = fs::write(format!("{}/cgroup.procs", DIRECT_CGROUP_DIR), old_pid.to_string());
                    }
                }
                self.proxied_pids = desired;
                return (true, format!("eBPF ACTIVE ({} PIDs hooked)", self.proxied_pids.len()));
            }
        }

        if Path::new("/sys/fs/bpf/waterwall_slots").exists() {
            let mut sorted: Vec<u32> = desired.iter().copied().collect();
            sorted.sort_unstable();
            let csv = sorted.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            if let Some(resp) = super::ipc::send_daemon_command(&format!("EBPF_PIDS {}", csv)) {
                if resp.starts_with("OK") {
                    self.proxied_pids = desired;
                    return (true, format!("eBPF ACTIVE ({} PIDs hooked)", self.proxied_pids.len()));
                }
            }
        }

        if !desired.is_empty() && !self.elevation_requested {
            self.elevation_requested = true;
            let _ = self.spawn_pkexec_helper();
        }

        (false, String::from("Restart 'sudo waterwall --daemon' or click Enable eBPF Hook"))
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

fn bpf_create_slot_map() -> Result<i32, i32> {
    #[repr(C)]
    struct MapCreateAttr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        _pad: [u32; 11],
    }
    let attr = MapCreateAttr { map_type: BPF_MAP_TYPE_ARRAY, key_size: 4, value_size: 8, max_entries: 4096, map_flags: 0, _pad: [0; 11] };
    let fd = unsafe { libc::syscall(libc::SYS_bpf, BPF_MAP_CREATE, &attr as *const MapCreateAttr, std::mem::size_of::<MapCreateAttr>()) };
    if fd < 0 { Err(unsafe { *libc::__errno_location() }) } else { Ok(fd as i32) }
}

fn bpf_pin_map(map_fd: i32) -> Result<(), i32> {
    let _ = fs::remove_file("/sys/fs/bpf/waterwall_slots");
    #[repr(C)]
    struct ObjPinAttr { pathname: u64, bpf_fd: u32, file_flags: u32 }
    let attr = ObjPinAttr { pathname: PINNED_SLOT_MAP_PATH.as_ptr() as u64, bpf_fd: map_fd as u32, file_flags: 0 };
    let ret = unsafe { libc::syscall(libc::SYS_bpf, BPF_OBJ_PIN, &attr as *const ObjPinAttr, std::mem::size_of::<ObjPinAttr>()) };
    if ret == 0 {
        unsafe { libc::chmod(PINNED_SLOT_MAP_PATH.as_ptr() as *const libc::c_char, 0o666) };
        Ok(())
    } else {
        Err(unsafe { *libc::__errno_location() })
    }
}

fn bpf_obj_get_map() -> i32 {
    #[repr(C)]
    struct ObjGetAttr { pathname: u64, bpf_fd: u32, file_flags: u32 }
    let attr = ObjGetAttr { pathname: PINNED_SLOT_MAP_PATH.as_ptr() as u64, bpf_fd: 0, file_flags: 0 };
    unsafe { libc::syscall(libc::SYS_bpf, BPF_OBJ_GET, &attr as *const ObjGetAttr, std::mem::size_of::<ObjGetAttr>()) as i32 }
}

fn bpf_load_connect4_prog(map_fd: i32, relay_port: u16) -> Result<i32, String> {
    let port_be = relay_port.to_be() as i32;
    let quic_port_be = 443u16.to_be() as i32;

    let insns: [BpfInsn; 43] = [
        BpfInsn::new(0xbf, 6, 1, 0, 0),            // [0] r6 = r1 (ctx)
        BpfInsn::new(0x61, 2, 6, 32, 0),           // [1] r2 = ctx->type
        BpfInsn::new(0x61, 8, 6, 24, 0),           // [2] r8 = ctx->user_port
        BpfInsn::new(0x55, 2, 0, 2, 2),            // [3] if r2 != SOCK_DGRAM(2) goto [6]
        BpfInsn::new(0x55, 8, 0, 34, quic_port_be),// [4] if port != 443 goto allow [39]
        BpfInsn::new(0x05, 0, 0, 35, 0),           // [5] goto deny [41] (block QUIC UDP/443)
        BpfInsn::new(0x55, 2, 0, 32, 1),           // [6] if r2 != SOCK_STREAM(1) goto allow [39]
        BpfInsn::new(0x61, 7, 6, 4, 0),            // [7] r7 = ctx->user_ip4
        BpfInsn::new(0xbf, 2, 7, 0, 0),            // [8] r2 = r7
        BpfInsn::new(0x57, 2, 0, 0, 0xFF),         // [9] r2 &= 0xFF
        BpfInsn::new(0x15, 2, 0, 28, 127),         // [10] if o0 == 127 goto allow [39]
        BpfInsn::new(0x15, 2, 0, 27, 10),          // [11] if o0 == 10 goto allow [39]
        BpfInsn::new(0x15, 2, 0, 26, 0),           // [12] if o0 == 0 goto allow [39]
        BpfInsn::new(0xbf, 3, 7, 0, 0),            // [13] r3 = r7
        BpfInsn::new(0x57, 3, 0, 0, 0xFFFF),       // [14] r3 &= 0xFFFF
        BpfInsn::new(0x15, 3, 0, 23, 0xA8C0),      // [15] if 192.168.0.0/16 goto allow [39]
        BpfInsn::new(0x57, 3, 0, 0, 0xF0FF),       // [16] r3 &= 0xF0FF
        BpfInsn::new(0x15, 3, 0, 21, 0x10AC),      // [17] if 172.16.0.0/12 goto allow [39]
        BpfInsn::new(0x85, 0, 0, 0, 7),            // [18] call bpf_get_prandom_u32 (7)
        BpfInsn::new(0x57, 0, 0, 0, 0x0FFE),       // [19] r0 &= 0x0FFE
        BpfInsn::new(0x07, 0, 0, 0, 1),            // [20] r0 += 1 (slot 1..=4095)
        BpfInsn::new(0xbf, 9, 0, 0, 0),            // [21] r9 = r0 (slot)
        BpfInsn::new(0x63, 10, 9, -4, 0),          // [22] *(u32 *)(r10 - 4) = r9 (key)
        BpfInsn::new(0x67, 8, 0, 0, 32),           // [23] r8 <<= 32
        BpfInsn::new(0x4f, 7, 8, 0, 0),            // [24] r7 |= r8
        BpfInsn::new(0x7b, 10, 7, -16, 0),         // [25] *(u64 *)(r10 - 16) = r7 (val)
        BpfInsn::new(0x18, 1, 1, 0, map_fd),       // [26] ld_imm64 r1 = map_fd
        BpfInsn::new(0x00, 0, 0, 0, 0),            // [27] ld_imm64 high
        BpfInsn::new(0xbf, 2, 10, 0, 0),           // [28] r2 = r10
        BpfInsn::new(0x07, 2, 0, 0, -4),           // [29] r2 += -4
        BpfInsn::new(0xbf, 3, 10, 0, 0),           // [30] r3 = r10
        BpfInsn::new(0x07, 3, 0, 0, -16),          // [31] r3 += -16
        BpfInsn::new(0xb7, 4, 0, 0, 0),            // [32] r4 = 0
        BpfInsn::new(0x85, 0, 0, 0, 2),            // [33] call bpf_map_update_elem (2)
        BpfInsn::new(0x67, 9, 0, 0, 16),           // [34] r9 <<= 16
        BpfInsn::new(0x47, 9, 0, 0, 0x647F),       // [35] r9 |= 0x647F (127.100.<lo>.<hi>)
        BpfInsn::new(0x63, 6, 9, 4, 0),            // [36] ctx->user_ip4 = r9
        BpfInsn::new(0xb7, 1, 0, 0, port_be),      // [37] r1 = htons(relay_port)
        BpfInsn::new(0x63, 6, 1, 24, 0),           // [38] ctx->user_port = r1
        BpfInsn::new(0xb7, 0, 0, 0, 1),            // [39] allow: r0 = 1
        BpfInsn::new(0x95, 0, 0, 0, 0),            // [40] exit
        BpfInsn::new(0xb7, 0, 0, 0, 0),            // [41] deny: r0 = 0
        BpfInsn::new(0x95, 0, 0, 0, 0),            // [42] exit
    ];

    load_sock_addr_prog(&insns, BPF_CGROUP_INET4_CONNECT, b"ww_connect4\0")
}

fn bpf_load_connect6_prog(relay_port: u16) -> Result<i32, String> {
    let port_be = relay_port.to_be() as i32;
    let quic_port_be = 443u16.to_be() as i32;

    let insns: [BpfInsn; 28] = [
        BpfInsn::new(0xbf, 6, 1, 0, 0),            // [0] r6 = r1 (ctx)
        BpfInsn::new(0x61, 2, 6, 32, 0),           // [1] r2 = ctx->type
        BpfInsn::new(0x61, 8, 6, 24, 0),           // [2] r8 = ctx->user_port
        BpfInsn::new(0x55, 2, 0, 2, 2),            // [3] if r2 != SOCK_DGRAM(2) goto [6]
        BpfInsn::new(0x55, 8, 0, 19, quic_port_be),// [4] if port != 443 goto allow [24]
        BpfInsn::new(0x05, 0, 0, 20, 0),           // [5] goto deny [26] (block QUIC UDP/443)
        BpfInsn::new(0x55, 2, 0, 17, 1),           // [6] if r2 != SOCK_STREAM(1) goto allow [24]
        BpfInsn::new(0x61, 2, 6, 8, 0),            // [7] r2 = ctx->user_ip6[0]
        BpfInsn::new(0x61, 3, 6, 12, 0),           // [8] r3 = ctx->user_ip6[1]
        BpfInsn::new(0x61, 4, 6, 16, 0),           // [9] r4 = ctx->user_ip6[2]
        BpfInsn::new(0x61, 5, 6, 20, 0),           // [10] r5 = ctx->user_ip6[3]
        BpfInsn::new(0x4f, 2, 3, 0, 0),            // [11] r2 |= r3
        BpfInsn::new(0x4f, 2, 4, 0, 0),            // [12] r2 |= r4
        BpfInsn::new(0x55, 2, 0, 2, 0),            // [13] if r2 != 0 goto redirect [16]
        BpfInsn::new(0x15, 5, 0, 9, 0x01000000),   // [14] if r5 == ::1 goto allow [24]
        BpfInsn::new(0x15, 5, 0, 8, 0),            // [15] if r5 == :: goto allow [24]
        BpfInsn::new(0xb7, 1, 0, 0, 0),            // [16] redirect: r1 = 0
        BpfInsn::new(0x63, 6, 1, 8, 0),            // [17] ctx->user_ip6[0] = 0
        BpfInsn::new(0x63, 6, 1, 12, 0),           // [18] ctx->user_ip6[1] = 0
        BpfInsn::new(0x63, 6, 1, 16, 0),           // [19] ctx->user_ip6[2] = 0
        BpfInsn::new(0xb7, 1, 0, 0, 0x01000000),   // [20] r1 = htonl(1) (::1)
        BpfInsn::new(0x63, 6, 1, 20, 0),           // [21] ctx->user_ip6[3] = ::1
        BpfInsn::new(0xb7, 1, 0, 0, port_be),      // [22] r1 = htons(relay_port)
        BpfInsn::new(0x63, 6, 1, 24, 0),           // [23] ctx->user_port = r1
        BpfInsn::new(0xb7, 0, 0, 0, 1),            // [24] allow: r0 = 1
        BpfInsn::new(0x95, 0, 0, 0, 0),            // [25] exit
        BpfInsn::new(0xb7, 0, 0, 0, 0),            // [26] deny: r0 = 0
        BpfInsn::new(0x95, 0, 0, 0, 0),            // [27] exit
    ];
    load_sock_addr_prog(&insns, BPF_CGROUP_INET6_CONNECT, b"ww_connect6\0")
}

fn load_sock_addr_prog(insns: &[BpfInsn], attach_type: u32, prog_label: &[u8; 12]) -> Result<i32, String> {
    let license = b"GPL\0";
    let mut log_buf = vec![0u8; 4096];

    #[repr(C)]
    struct ProgLoadAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
        _pad: [u32; 16],
    }

    let mut name = [0u8; 16];
    name[..12].copy_from_slice(prog_label);

    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: name,
        prog_ifindex: 0,
        expected_attach_type: attach_type,
        _pad: [0; 16],
    };

    let fd = unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_LOAD, &attr as *const ProgLoadAttr, std::mem::size_of::<ProgLoadAttr>()) };
    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let log_end = log_buf.iter().position(|&b| b == 0).unwrap_or(0);
        let log_s = String::from_utf8_lossy(&log_buf[..log_end]);
        Err(format!("errno={} {}", errno, log_s.lines().last().unwrap_or("")))
    } else {
        Ok(fd as i32)
    }
}

fn bpf_attach_cgroup(cgroup_fd: i32, prog_fd: i32, attach_type: u32) -> Result<(), i32> {
    #[repr(C)]
    struct AttachAttr { target_fd: u32, attach_bpf_fd: u32, attach_type: u32, attach_flags: u32, replace_bpf_fd: u32 }
    let attr = AttachAttr { target_fd: cgroup_fd as u32, attach_bpf_fd: prog_fd as u32, attach_type, attach_flags: BPF_F_ALLOW_OVERRIDE, replace_bpf_fd: 0 };
    let ret = unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_ATTACH, &attr as *const AttachAttr, std::mem::size_of::<AttachAttr>()) };
    if ret == 0 { Ok(()) } else { Err(unsafe { *libc::__errno_location() }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_proxied_pids_from_saved_config() {
        let pids = super::super::ipc::scan_saved_config_proxied_pids();
        println!("Resolved proxied PIDs from flow_graph.cfg: {:?}", pids);
        let lw_pids = resolve_pids_for_app_names(&["librewolf".to_string()], &[]);
        println!("Resolved librewolf PIDs: {:?}", lw_pids);
    }
}
