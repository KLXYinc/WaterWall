pub mod dns;
pub mod ebpf_redirect;
pub mod geoip;
pub mod ipc;
pub mod killer;
pub mod monitor;
pub mod protocol;
pub mod proxy_relay;
pub mod records;
pub mod scanner;
pub mod socket;

pub use dns::{DnsEvent, DnsResolver};
pub use ebpf_redirect::{
    lookup_orig_dst_slot, request_ebpf_elevation, resolve_pids_for_app_names,
    sync_ebpf_for_apps, sync_ebpf_proxied_pids, unmap_ebpf_addr,
};
pub use geoip::{classify_ip_location_with_domain, infer_country_from_domain, IpLocationInfo};
pub use ipc::{run_daemon_server, send_daemon_command};
pub use killer::{terminate_single_socket, terminate_sockets};
pub use monitor::NetworkMonitor;
pub use protocol::{classify_traffic_type, CountryCode};
pub use proxy_relay::{LocalProxyRelay, UpstreamProxyConfig, UpstreamProxyKind, LOCAL_RELAY_PORT};
pub use records::{
    AlertKind, HostRecord, NetworkSnapshot, ProtocolRecord, SecurityAlert, HISTORY_LEN,
};
pub use scanner::{
    read_system_net_dev, scan_all_sockets, scan_process_metadata, scan_vpn_interfaces, ProcSocket,
    ProcessMetadata, VpnInterfaceInfo,
};
pub use socket::{
    app_category_badge, format_bytes, format_speed, is_remote_ip, AppNetworkInfo, ConnectionInfo,
    Protocol, SocketState,
};
