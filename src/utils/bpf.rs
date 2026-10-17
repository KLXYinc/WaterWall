use std::fs;

const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_OBJ_PIN: libc::c_long = 6;
const BPF_OBJ_GET: libc::c_long = 7;
const BPF_PROG_ATTACH: libc::c_long = 8;

const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
const BPF_F_ALLOW_OVERRIDE: u32 = 1;

pub const PINNED_SLOT_MAP_PATH: &str = "/sys/fs/bpf/waterwall_slots\0";

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst & 0x0F) | ((src & 0x0F) << 4),
            off,
            imm,
        }
    }
}

pub fn bpf_lookup_u64_elem(map_fd: i32, slot: u32) -> Option<u64> {
    #[repr(C)]
    struct MapElemAttr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let key: u32 = slot;
    let mut val: u64 = 0;
    let attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad: 0,
        key: &key as *const u32 as u64,
        value: &mut val as *mut u64 as u64,
        flags: 0,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const MapElemAttr,
            std::mem::size_of::<MapElemAttr>(),
        )
    };
    (ret == 0 && val != 0).then_some(val)
}

pub fn bpf_create_slot_map() -> Result<i32, i32> {
    #[repr(C)]
    struct MapCreateAttr {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        _pad: [u32; 11],
    }
    let attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 4096,
        map_flags: 0,
        _pad: [0; 11],
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const MapCreateAttr,
            std::mem::size_of::<MapCreateAttr>(),
        )
    };
    if fd < 0 {
        Err(unsafe { *libc::__errno_location() })
    } else {
        Ok(fd as i32)
    }
}

pub fn bpf_pin_map(map_fd: i32) -> Result<(), i32> {
    let _ = fs::remove_file("/sys/fs/bpf/waterwall_slots");
    #[repr(C)]
    struct ObjPinAttr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let attr = ObjPinAttr {
        pathname: PINNED_SLOT_MAP_PATH.as_ptr() as u64,
        bpf_fd: map_fd as u32,
        file_flags: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_PIN,
            &attr as *const ObjPinAttr,
            std::mem::size_of::<ObjPinAttr>(),
        )
    };
    if ret == 0 {
        unsafe { libc::chmod(PINNED_SLOT_MAP_PATH.as_ptr() as *const libc::c_char, 0o666) };
        Ok(())
    } else {
        Err(unsafe { *libc::__errno_location() })
    }
}

pub fn bpf_obj_get_map() -> i32 {
    #[repr(C)]
    struct ObjGetAttr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let attr = ObjGetAttr {
        pathname: PINNED_SLOT_MAP_PATH.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr as *const ObjGetAttr,
            std::mem::size_of::<ObjGetAttr>(),
        ) as i32
    }
}

pub fn bpf_load_connect4_prog(map_fd: i32, relay_port: u16) -> Result<i32, String> {
    let port_be = relay_port.to_be() as i32;
    let quic_port_be = 443u16.to_be() as i32;

    let insns: [BpfInsn; 43] = [
        BpfInsn::new(0xbf, 6, 1, 0, 0),             // [0] r6 = r1 (ctx)
        BpfInsn::new(0x61, 2, 6, 32, 0),            // [1] r2 = ctx->type
        BpfInsn::new(0x61, 8, 6, 24, 0),            // [2] r8 = ctx->user_port
        BpfInsn::new(0x55, 2, 0, 2, 2),             // [3] if r2 != SOCK_DGRAM(2) goto [6]
        BpfInsn::new(0x55, 8, 0, 34, quic_port_be), // [4] if port != 443 goto allow [39]
        BpfInsn::new(0x05, 0, 0, 35, 0),            // [5] goto deny [41] (block QUIC UDP/443)
        BpfInsn::new(0x55, 2, 0, 32, 1),            // [6] if r2 != SOCK_STREAM(1) goto allow [39]
        BpfInsn::new(0x61, 7, 6, 4, 0),             // [7] r7 = ctx->user_ip4
        BpfInsn::new(0xbf, 2, 7, 0, 0),             // [8] r2 = r7
        BpfInsn::new(0x57, 2, 0, 0, 0xFF),          // [9] r2 &= 0xFF
        BpfInsn::new(0x15, 2, 0, 28, 127),          // [10] if o0 == 127 goto allow [39]
        BpfInsn::new(0x15, 2, 0, 27, 10),           // [11] if o0 == 10 goto allow [39]
        BpfInsn::new(0x15, 2, 0, 26, 0),            // [12] if o0 == 0 goto allow [39]
        BpfInsn::new(0xbf, 3, 7, 0, 0),             // [13] r3 = r7
        BpfInsn::new(0x57, 3, 0, 0, 0xFFFF),        // [14] r3 &= 0xFFFF
        BpfInsn::new(0x15, 3, 0, 23, 0xA8C0),       // [15] if 192.168.0.0/16 goto allow [39]
        BpfInsn::new(0x57, 3, 0, 0, 0xF0FF),        // [16] r3 &= 0xF0FF
        BpfInsn::new(0x15, 3, 0, 21, 0x10AC),       // [17] if 172.16.0.0/12 goto allow [39]
        BpfInsn::new(0x85, 0, 0, 0, 7),             // [18] call bpf_get_prandom_u32 (7)
        BpfInsn::new(0x57, 0, 0, 0, 0x0FFE),        // [19] r0 &= 0x0FFE
        BpfInsn::new(0x07, 0, 0, 0, 1),             // [20] r0 += 1 (slot 1..=4095)
        BpfInsn::new(0xbf, 9, 0, 0, 0),             // [21] r9 = r0 (slot)
        BpfInsn::new(0x63, 10, 9, -4, 0),           // [22] *(u32 *)(r10 - 4) = r9 (key)
        BpfInsn::new(0x67, 8, 0, 0, 32),            // [23] r8 <<= 32
        BpfInsn::new(0x4f, 7, 8, 0, 0),             // [24] r7 |= r8
        BpfInsn::new(0x7b, 10, 7, -16, 0),          // [25] *(u64 *)(r10 - 16) = r7 (val)
        BpfInsn::new(0x18, 1, 1, 0, map_fd),        // [26] ld_imm64 r1 = map_fd
        BpfInsn::new(0x00, 0, 0, 0, 0),             // [27] ld_imm64 high
        BpfInsn::new(0xbf, 2, 10, 0, 0),            // [28] r2 = r10
        BpfInsn::new(0x07, 2, 0, 0, -4),            // [29] r2 += -4
        BpfInsn::new(0xbf, 3, 10, 0, 0),            // [30] r3 = r10
        BpfInsn::new(0x07, 3, 0, 0, -16),           // [31] r3 += -16
        BpfInsn::new(0xb7, 4, 0, 0, 0),             // [32] r4 = 0
        BpfInsn::new(0x85, 0, 0, 0, 2),             // [33] call bpf_map_update_elem (2)
        BpfInsn::new(0x67, 9, 0, 0, 16),            // [34] r9 <<= 16
        BpfInsn::new(0x47, 9, 0, 0, 0x647F),        // [35] r9 |= 0x647F (127.100.<lo>.<hi>)
        BpfInsn::new(0x63, 6, 9, 4, 0),             // [36] ctx->user_ip4 = r9
        BpfInsn::new(0xb7, 1, 0, 0, port_be),       // [37] r1 = htons(relay_port)
        BpfInsn::new(0x63, 6, 1, 24, 0),            // [38] ctx->user_port = r1
        BpfInsn::new(0xb7, 0, 0, 0, 1),             // [39] allow: r0 = 1
        BpfInsn::new(0x95, 0, 0, 0, 0),             // [40] exit
        BpfInsn::new(0xb7, 0, 0, 0, 0),             // [41] deny: r0 = 0
        BpfInsn::new(0x95, 0, 0, 0, 0),             // [42] exit
    ];

    load_sock_addr_prog(&insns, BPF_CGROUP_INET4_CONNECT, b"ww_connect4\0")
}

pub fn bpf_load_connect6_prog(relay_port: u16) -> Result<i32, String> {
    let port_be = relay_port.to_be() as i32;
    let quic_port_be = 443u16.to_be() as i32;

    let insns: [BpfInsn; 28] = [
        BpfInsn::new(0xbf, 6, 1, 0, 0),             // [0] r6 = r1 (ctx)
        BpfInsn::new(0x61, 2, 6, 32, 0),            // [1] r2 = ctx->type
        BpfInsn::new(0x61, 8, 6, 24, 0),            // [2] r8 = ctx->user_port
        BpfInsn::new(0x55, 2, 0, 2, 2),             // [3] if r2 != SOCK_DGRAM(2) goto [6]
        BpfInsn::new(0x55, 8, 0, 19, quic_port_be), // [4] if port != 443 goto allow [24]
        BpfInsn::new(0x05, 0, 0, 20, 0),            // [5] goto deny [26] (block QUIC UDP/443)
        BpfInsn::new(0x55, 2, 0, 17, 1),            // [6] if r2 != SOCK_STREAM(1) goto allow [24]
        BpfInsn::new(0x61, 2, 6, 8, 0),             // [7] r2 = ctx->user_ip6[0]
        BpfInsn::new(0x61, 3, 6, 12, 0),            // [8] r3 = ctx->user_ip6[1]
        BpfInsn::new(0x61, 4, 6, 16, 0),            // [9] r4 = ctx->user_ip6[2]
        BpfInsn::new(0x61, 5, 6, 20, 0),            // [10] r5 = ctx->user_ip6[3]
        BpfInsn::new(0x4f, 2, 3, 0, 0),             // [11] r2 |= r3
        BpfInsn::new(0x4f, 2, 4, 0, 0),             // [12] r2 |= r4
        BpfInsn::new(0x55, 2, 0, 2, 0),             // [13] if r2 != 0 goto redirect [16]
        BpfInsn::new(0x15, 5, 0, 9, 0x01000000),    // [14] if r5 == ::1 goto allow [24]
        BpfInsn::new(0x15, 5, 0, 8, 0),             // [15] if r5 == :: goto allow [24]
        BpfInsn::new(0xb7, 1, 0, 0, 0),             // [16] redirect: r1 = 0
        BpfInsn::new(0x63, 6, 1, 8, 0),             // [17] ctx->user_ip6[0] = 0
        BpfInsn::new(0x63, 6, 1, 12, 0),            // [18] ctx->user_ip6[1] = 0
        BpfInsn::new(0x63, 6, 1, 16, 0),            // [19] ctx->user_ip6[2] = 0
        BpfInsn::new(0xb7, 1, 0, 0, 0x01000000),    // [20] r1 = htonl(1) (::1)
        BpfInsn::new(0x63, 6, 1, 20, 0),            // [21] ctx->user_ip6[3] = ::1
        BpfInsn::new(0xb7, 1, 0, 0, port_be),       // [22] r1 = htons(relay_port)
        BpfInsn::new(0x63, 6, 1, 24, 0),            // [23] ctx->user_port = r1
        BpfInsn::new(0xb7, 0, 0, 0, 1),             // [24] allow: r0 = 1
        BpfInsn::new(0x95, 0, 0, 0, 0),             // [25] exit
        BpfInsn::new(0xb7, 0, 0, 0, 0),             // [26] deny: r0 = 0
        BpfInsn::new(0x95, 0, 0, 0, 0),             // [27] exit
    ];
    load_sock_addr_prog(&insns, BPF_CGROUP_INET6_CONNECT, b"ww_connect6\0")
}

fn load_sock_addr_prog(
    insns: &[BpfInsn],
    attach_type: u32,
    prog_label: &[u8; 12],
) -> Result<i32, String> {
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

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD,
            &attr as *const ProgLoadAttr,
            std::mem::size_of::<ProgLoadAttr>(),
        )
    };
    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let log_end = log_buf.iter().position(|&b| b == 0).unwrap_or(0);
        let log_s = String::from_utf8_lossy(&log_buf[..log_end]);
        Err(format!(
            "errno={} {}",
            errno,
            log_s.lines().last().unwrap_or("")
        ))
    } else {
        Ok(fd as i32)
    }
}

pub fn bpf_attach_cgroup(cgroup_fd: i32, prog_fd: i32, attach_type: u32) -> Result<(), i32> {
    #[repr(C)]
    struct AttachAttr {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
        replace_bpf_fd: u32,
    }
    let attr = AttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type,
        attach_flags: BPF_F_ALLOW_OVERRIDE,
        replace_bpf_fd: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &attr as *const AttachAttr,
            std::mem::size_of::<AttachAttr>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(unsafe { *libc::__errno_location() })
    }
}
