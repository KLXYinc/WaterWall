use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::socket::ConnectionInfo;

static RECENT_DROPS: Mutex<Option<HashMap<SocketAddr, Instant>>> = Mutex::new(None);
const DROP_COOLDOWN: Duration = Duration::from_millis(1500);

/// Terminate active kernel network sockets using Linux socket diagnostics / ss -K
pub fn terminate_sockets(connections: &[ConnectionInfo]) -> usize {
    let mut terminated = 0;

    for conn in connections {
        if conn.remote_addr.port() == 0 || conn.remote_addr.ip().is_unspecified() {
            continue;
        }

        if terminate_single_socket(&conn.remote_addr) {
            terminated += 1;
        }
    }

    terminated
}

/// Terminate an active TCP connection to a specific remote socket endpoint (rate-limited per endpoint)
pub fn terminate_single_socket(remote: &SocketAddr) -> bool {
    let now = Instant::now();
    if let Ok(mut guard) = RECENT_DROPS.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some(&last) = map.get(remote) {
            if now.duration_since(last) < DROP_COOLDOWN {
                return false;
            }
        }
        map.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
        map.insert(*remote, now);
    }

    let filter = format!("dst {} dport = :{}", remote.ip(), remote.port());
    let output = Command::new("ss").args(["-K", &filter]).output();

    matches!(output, Ok(out) if out.status.success())
}
