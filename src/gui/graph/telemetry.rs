use super::sync::NodeFlowAccum;
use super::Graph;
use crate::gui::nodes::NodeKind;
use crate::net::{format_bytes, format_speed, NetworkMonitor, NetworkSnapshot, HISTORY_LEN};

impl Graph {
    pub(super) fn update_node_telemetry(
        &mut self,
        snap: &NetworkSnapshot,
        monitor: &NetworkMonitor,
        node_accum: &[NodeFlowAccum],
        max_sys_bytes: f32,
        blackhole_all: bool,
        (ebpf_ok, ebpf_msg): (bool, String),
    ) {
        let flat_wave = [0.0f32; HISTORY_LEN];
        let idle_col = [0.52f32, 0.58, 0.68, 1.0];

        for (i, acc) in node_accum.iter().enumerate() {
            match self.nodes[i].kind {
                NodeKind::FilterNode => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("Status:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else {
                        let (mode_idx, _) = self.nodes[i].combo_selected("Mode:").unwrap_or((0, ""));
                        let ports = self.nodes[i].text_input("Ports:").unwrap_or("").trim();
                        let host = self.nodes[i].text_input("Host:").unwrap_or("").trim();
                        let (txt, col) = match mode_idx {
                            2 => ("DROP ALL ON PATH".to_string(), [0.98f32, 0.35, 0.35, 1.0]),
                            1 if !ports.is_empty() || !host.is_empty() => (
                                format!("BLOCK {} {}", ports, host),
                                [0.98f32, 0.78, 0.20, 1.0],
                            ),
                            0 if !ports.is_empty() || !host.is_empty() => (
                                format!("ALLOW {} {}", ports, host),
                                [0.25f32, 0.92, 0.68, 1.0],
                            ),
                            _ => (
                                format!("PASS ({})", format_speed(acc.speed)),
                                [0.25f32, 0.92, 0.68, 1.0],
                            ),
                        };
                        self.nodes[i].set_readout("Status:", txt, Some(col));
                    }
                }
                NodeKind::BlockNode => {
                    let (txt, col) = if !acc.has_input {
                        ("IDLE (NO INPUT)", idle_col)
                    } else {
                        ("BLOCKING & TCP RST", [0.98f32, 0.32, 0.35, 1.0])
                    };
                    self.nodes[i].set_readout("Action:", txt.to_string(), Some(col));
                }
                NodeKind::VpnNode => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("Status:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else {
                        let (_, proto_name) =
                            self.nodes[i].combo_selected("Proto:").unwrap_or((0, "WireGuard"));
                        let iface = self.nodes[i]
                            .text_input("Iface:")
                            .unwrap_or("wg0")
                            .trim()
                            .to_string();
                        let matched = snap
                            .vpn_interfaces
                            .iter()
                            .find(|v| v.name.eq_ignore_ascii_case(&iface));
                        let status_txt = match matched {
                            Some(v) if v.is_up => format!("UP: {} ({})", v.name, format_speed(acc.speed)),
                            _ => format!(
                                "{} [{}] · {}",
                                proto_name,
                                if iface.is_empty() { "wg0" } else { &iface },
                                format_speed(acc.speed)
                            ),
                        };
                        self.nodes[i].set_readout(
                            "Status:",
                            status_txt,
                            Some([0.20f32, 0.90, 0.78, 1.0]),
                        );
                    }
                }
                NodeKind::ProxyNode => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("Status:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else if !ebpf_ok {
                        self.nodes[i].set_readout(
                            "Status:",
                            ebpf_msg.clone(),
                            Some([0.98f32, 0.72, 0.22, 1.0]),
                        );
                    } else {
                        let relayed = monitor.proxy_relay.relayed_connections();
                        let srv = self.nodes[i]
                            .text_input("Server:")
                            .unwrap_or("127.0.0.1:1080")
                            .trim()
                            .to_string();
                        let has_auth = !self.nodes[i].text_input("User:").unwrap_or("").trim().is_empty();
                        let auth_tag = if has_auth { " [AUTH]" } else { "" };
                        self.nodes[i].set_readout(
                            "Status:",
                            format!("eBPF ON ({} tunneled) · {}{}", relayed, srv, auth_tag),
                            Some([0.22f32, 0.94, 0.72, 1.0]),
                        );
                    }
                }
                NodeKind::RateLimiter => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("Status:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else {
                        let cap = self.nodes[i].slider("Max Speed (KB/s)").unwrap_or(4096.0);
                        self.nodes[i].set_readout(
                            "Status:",
                            format!("CAP {:.0} KB/s ({})", cap, format_speed(acc.speed)),
                            Some([0.98f32, 0.68, 0.22, 1.0]),
                        );
                    }
                }
                NodeKind::TrafficMonitor => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("State:", "DISCONNECTED".to_string(), Some(idle_col));
                        self.nodes[i].set_data_meter(
                            "0 B/s".to_string(),
                            "0 B".to_string(),
                            0.0,
                            Some(idle_col),
                        );
                        self.nodes[i].set_wave(&flat_wave);
                    } else {
                        let (st, col) = if acc.reaches_gateway {
                            ("PROBING ACTIVE FLOW", [0.80f32, 0.55, 0.98, 1.0])
                        } else {
                            ("NO GATEWAY UPLINK", [0.98f32, 0.65, 0.22, 1.0])
                        };
                        let ratio = (acc.bytes as f32 / max_sys_bytes)
                            .max((acc.speed as f32) / (1024.0 * 1024.0 * 2.0))
                            .clamp(0.05, 1.0);
                        self.nodes[i].set_readout("State:", st.to_string(), Some(col));
                        self.nodes[i].set_data_meter(
                            format_speed(acc.speed),
                            format_bytes(acc.bytes),
                            ratio,
                            Some(col),
                        );
                        self.nodes[i].set_wave(&acc.wave);
                    }
                }
                NodeKind::InternetGateway => {
                    if !acc.has_input || blackhole_all {
                        self.nodes[i].set_data_meter(
                            "0 B/s".to_string(),
                            "0 B".to_string(),
                            0.0,
                            Some(idle_col),
                        );
                        self.nodes[i].set_readout(
                            "WAN In:",
                            if blackhole_all {
                                "BLACKHOLE DROP".to_string()
                            } else {
                                "DISCONNECTED".to_string()
                            },
                            Some(if blackhole_all {
                                [0.95f32, 0.30, 0.30, 1.0]
                            } else {
                                idle_col
                            }),
                        );
                        self.nodes[i].set_readout("LAN In:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else {
                        let ratio = (acc.bytes as f32 / max_sys_bytes)
                            .max((acc.speed as f32) / (1024.0 * 1024.0 * 2.0))
                            .clamp(0.06, 1.0);
                        self.nodes[i].set_data_meter(
                            format_speed(acc.speed),
                            format_bytes(acc.bytes),
                            ratio,
                            None,
                        );
                        self.nodes[i].set_readout(
                            "WAN In:",
                            format!("{} ({})", format_speed(acc.wan_speed), format_bytes(acc.wan_bytes)),
                            None,
                        );
                        self.nodes[i].set_readout(
                            "LAN In:",
                            format!("{} ({})", format_speed(acc.lan_speed), format_bytes(acc.lan_bytes)),
                            None,
                        );
                    }
                }
                _ => {}
            }
        }
    }
}
