pub mod item;
pub mod node;
pub mod pin;
pub mod probe;

pub use item::{Item, WAVE_SAMPLES};
pub use node::Node;
pub use pin::{pin_id, rope_kind_name, Link, Pin};
pub use probe::{ProbeConfig, ProbeVariant, ProbeWaveChannel};

use crate::gui::theme;

pub const PIN_REMOTE_WAN: [f32; 4] = [1.00, 0.72, 0.20, 1.0]; // Amber Gold (Remote WAN)
pub const PIN_LOCAL_LAN: [f32; 4] = [0.16, 0.92, 0.72, 1.0];  // Emerald Teal (Local LAN)

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NodeKind {
    AppGroup,        // App Group Source Node (2 Exits: Remote WAN & Local LAN)
    FilterNode,      // Port & Host Filter Node (1 In -> 1 Out)
    BlockNode,       // Firewall Kill Switch Sink (1 In -> Drops Traffic)
    VpnNode,         // VPN Tunnel Node — Remote WAN only (1 In -> 1 Out)
    ProxyNode,       // Proxy Server Node — Remote WAN only (1 In -> 1 Out)
    RateLimiter,     // QoS Bandwidth Shaper Node (1 In -> 1 Out)
    TrafficMonitor,  // Live Traffic Probe Node (1 In -> 1 Out, shows ONLY connected flow)
    InternetGateway, // Network Gateway Sink (2 Inputs: In: Remote WAN & In: Local LAN)
}

impl NodeKind {
    pub const GROUP_RULES: [NodeKind; 5] = [
        NodeKind::FilterNode,
        NodeKind::BlockNode,
        NodeKind::VpnNode,
        NodeKind::ProxyNode,
        NodeKind::RateLimiter,
    ];
    pub const PROBES: [NodeKind; 1] = [NodeKind::TrafficMonitor];

    pub fn is_deletable(self) -> bool {
        !matches!(self, NodeKind::InternetGateway)
    }

    pub fn is_wan_only(self) -> bool {
        matches!(self, NodeKind::VpnNode | NodeKind::ProxyNode)
    }

    pub fn title(self) -> &'static str {
        match self {
            NodeKind::AppGroup => "App Group: All Apps",
            NodeKind::FilterNode => "Filter Node (Port / Host)",
            NodeKind::BlockNode => "Block Node (Kill Switch)",
            NodeKind::VpnNode => "VPN Tunnel (WAN Only)",
            NodeKind::ProxyNode => "Proxy Server (WAN Only)",
            NodeKind::RateLimiter => "Rate Limiter (QoS)",
            NodeKind::TrafficMonitor => "Live Traffic Probe",
            NodeKind::InternetGateway => "Network Gateway (WAN & LAN)",
        }
    }

    pub fn width(self) -> f32 {
        match self {
            NodeKind::AppGroup => 258.0,
            NodeKind::FilterNode => 248.0,
            NodeKind::BlockNode => 235.0,
            NodeKind::VpnNode => 250.0,
            NodeKind::ProxyNode => 270.0,
            NodeKind::RateLimiter => 230.0,
            NodeKind::TrafficMonitor => 274.0,
            NodeKind::InternetGateway => 248.0,
        }
    }

    pub fn accent(self) -> [f32; 4] {
        theme::accent_for(self)
    }

    pub fn default_items(self, id: i32) -> Vec<Item> {
        let acc = theme::accent_for(self);
        match self {
            // Source: 2 exits (Out: Remote WAN and Out: Local LAN)
            NodeKind::AppGroup => vec![
                Item::pin_out_colored(pin_id(id, 1), "Out: Remote WAN", PIN_REMOTE_WAN),
                Item::pin_out_colored(pin_id(id, 2), "Out: Local LAN", PIN_LOCAL_LAN),
                Item::data_meter(acc),
                Item::group_apps_button(),
                Item::readout("Sockets:", "0 WAN / 0 LAN", [0.62, 0.74, 0.88, 1.0]),
                Item::wave(acc),
            ],
            // Processing nodes: 1 In -> 1 Out
            NodeKind::FilterNode => vec![
                Item::pin_in(pin_id(id, 1), "In (Stream)"),
                Item::readout("Status:", "DISCONNECTED", [0.55, 0.62, 0.72, 1.0]),
                Item::combo(
                    "Mode:",
                    &["Allow Matching", "Block Matching", "Drop All on Path"],
                    0,
                ),
                Item::text_input("Ports:", "", "e.g. 80, 443"),
                Item::text_input("Host:", "", "domain or IP"),
                Item::pin_out(pin_id(id, 2), "Out (Filtered)"),
            ],
            NodeKind::BlockNode => vec![
                Item::pin_in(pin_id(id, 1), "In (Stream to Block)"),
                Item::readout("Action:", "IDLE (NO INPUT)", [0.55, 0.62, 0.72, 1.0]),
                Item::checkbox("Kill Active Sockets", true),
            ],
            NodeKind::VpnNode => vec![
                Item::pin_in_colored(pin_id(id, 1), "In: Remote WAN", PIN_REMOTE_WAN),
                Item::readout("Status:", "DISCONNECTED", [0.55, 0.62, 0.72, 1.0]),
                Item::combo(
                    "Proto:",
                    &["WireGuard", "OpenVPN / TUN", "Tailscale", "IPsec / IKEv2"],
                    0,
                ),
                Item::text_input("Iface:", "wg0", "wg0, tun0, tailscale0"),
                Item::checkbox("Kill-Switch on Drop", false),
                Item::pin_out_colored(pin_id(id, 2), "Out: VPN WAN", PIN_REMOTE_WAN),
            ],
            NodeKind::ProxyNode => vec![
                Item::pin_in_colored(pin_id(id, 1), "In: Remote WAN", PIN_REMOTE_WAN),
                Item::readout("Status:", "DISCONNECTED", [0.55, 0.62, 0.72, 1.0]),
                Item::action_button("Paste Proxy URL (Clipboard)"),
                Item::combo(
                    "Type:",
                    &["SOCKS5", "HTTP CONNECT", "Tor SOCKS (9050)", "Shadowsocks"],
                    1,
                ),
                Item::text_input("Server:", "127.0.0.1:1080", "host:port or paste URL"),
                Item::text_input("User:", "", "username"),
                Item::text_input("Pass:", "", "password / session"),
                Item::checkbox("Proxy DNS Queries", true),
                Item::pin_out_colored(pin_id(id, 2), "Out: Proxied WAN", PIN_REMOTE_WAN),
            ],
            NodeKind::RateLimiter => vec![
                Item::pin_in(pin_id(id, 1), "In (Stream)"),
                Item::readout("Status:", "DISCONNECTED", [0.55, 0.62, 0.72, 1.0]),
                Item::slider("Max Speed (KB/s)", 10.0, 50000.0, 4096.0),
                Item::pin_out(pin_id(id, 2), "Out (Shaped)"),
            ],
            NodeKind::TrafficMonitor => vec![
                Item::pin_in(pin_id(id, 1), "In (Probe)"),
                Item::readout("State:", "DISCONNECTED", [0.55, 0.62, 0.72, 1.0]),
                Item::data_meter(acc),
                Item::readout("In / Out:", "▼ 0 B/s  ▲ 0 B/s", [0.68, 0.78, 0.90, 1.0]),
                Item::readout("Flow:", "0 active / 0 sockets", [0.68, 0.78, 0.90, 1.0]),
                Item::readout("Target:", "No active stream", [0.62, 0.72, 0.84, 1.0]),
                Item::wave(acc),
                Item::pin_out(pin_id(id, 2), "Out (Pass)"),
            ],
            // Gateway Sink: 2 inputs (In: Remote WAN and In: Local LAN)
            NodeKind::InternetGateway => vec![
                Item::pin_in_colored(pin_id(id, 1), "In: Remote WAN", PIN_REMOTE_WAN),
                Item::pin_in_colored(pin_id(id, 2), "In: Local LAN", PIN_LOCAL_LAN),
                Item::data_meter(acc),
                Item::readout("WAN In:", "0 B/s", PIN_REMOTE_WAN),
                Item::readout("LAN In:", "0 B/s", PIN_LOCAL_LAN),
                Item::checkbox("Blackhole Drop All", false),
            ],
        }
    }
}
