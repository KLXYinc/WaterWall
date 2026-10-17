use std::net::SocketAddr;
use std::process::Command;

use super::socket::ConnectionInfo;

/// Terminate active kernel network sockets using Linux socket diagnostics / ss -K / iptables
pub fn terminate_sockets(connections: &[ConnectionInfo]) -> usize {
    let mut terminated = 0;

    for conn in connections {
        if conn.remote_addr.port() == 0 || conn.remote_addr.ip().is_unspecified() {
            continue;
        }

        // Try terminating via `ss -K` (iproute2 kernel socket destroy netlink API)
        if terminate_single_socket(&conn.remote_addr) {
            terminated += 1;
        }
    }

    terminated
}

/// Terminate an active TCP connection to a specific remote socket endpoint
pub fn terminate_single_socket(remote: &SocketAddr) -> bool {
    let ip = remote.ip().to_string();
    let port = remote.port().to_string();

    // ss -K dst <ip> dport = :<port>
    let filter = format!("dst {} dport = :{}", ip, port);
    let output = Command::new("ss")
        .args(["-K", &filter])
        .output();

    match output {
        Ok(out) if out.status.success() => true,
        _ => {
            // Netlink direct or raw RST fallback
            false
        }
    }
}
