use super::nodes::NodeKind;

pub const BACKDROP: [f32; 3] = [0.078, 0.082, 0.094];
pub const WINDOW_BG: [f32; 4] = [BACKDROP[0], BACKDROP[1], BACKDROP[2], 1.0];
pub const INITIAL_PAN: [f32; 2] = [48.0, 40.0];

pub const PIN_INPUT: [f32; 4] = [0.22, 0.68, 1.00, 1.0];
pub const PIN_OUTPUT: [f32; 4] = [1.00, 0.74, 0.22, 1.0];

pub fn accent_for(kind: NodeKind) -> [f32; 4] {
    match kind {
        NodeKind::AppGroup => [0.15, 0.88, 0.65, 1.0],        // Emerald Mint (App Groups)
        NodeKind::FilterNode => [0.98, 0.78, 0.18, 1.0],      // Amber Gold (Filter Node)
        NodeKind::BlockNode => [0.95, 0.26, 0.30, 1.0],       // Crimson Red (Block / Kill Switch)
        NodeKind::VpnNode => [0.16, 0.82, 0.96, 1.0],         // Electric Cyan (VPN Tunnel)
        NodeKind::ProxyNode => [0.38, 0.62, 0.98, 1.0],       // Indigo Blue (Proxy Server)
        NodeKind::RateLimiter => [0.98, 0.54, 0.22, 1.0],     // Tangerine (QoS Rate Limiter)
        NodeKind::TrafficMonitor => [0.72, 0.42, 0.96, 1.0],  // Violet Purple (Live Probe)
        NodeKind::InternetGateway => [0.28, 0.56, 0.98, 1.0], // Royal Blue (WAN Gateway)
    }
}
