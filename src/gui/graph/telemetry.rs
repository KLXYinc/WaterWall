use super::flow_calc::NodeFlowAccum;
use super::Graph;
use crate::gui::nodes::{NodeKind, ProbeVariant, ProbeWaveChannel};
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
                            _ if acc.speed >= 1.0 => (
                                format!("PASS ({})", format_speed(acc.speed)),
                                [0.25f32, 0.92, 0.68, 1.0],
                            ),
                            _ => (
                                format!("IDLE ({} socks)", acc.total_sockets),
                                [0.58f32, 0.68, 0.80, 1.0],
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
                    update_probe_node(&mut self.nodes[i], acc, max_sys_bytes, &flat_wave, idle_col);
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
                            .clamp(0.04, 1.0);
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

fn update_probe_node(
    node: &mut crate::gui::nodes::Node,
    acc: &NodeFlowAccum,
    max_sys_bytes: f32,
    flat_wave: &[f32; HISTORY_LEN],
    idle_col: [f32; 4],
) {
    if !acc.has_input {
        node.set_readout_nth(0, "State:", "DISCONNECTED".to_string(), Some(idle_col));
        node.set_data_meter("0 B/s".to_string(), "0 B".to_string(), 0.0, Some(idle_col));
        node.set_readout_nth(1, "In / Out:", "—".to_string(), Some(idle_col));
        node.set_readout_nth(2, "Flow:", "No input rope".to_string(), Some(idle_col));
        node.set_readout_nth(3, "Target:", "Connect rope to probe".to_string(), Some(idle_col));
        node.set_wave(flat_wave);
        return;
    }

    let scope_tag = match (acc.has_wan, acc.has_lan) {
        (true, true) => "WAN+LAN",
        (true, false) => "REMOTE WAN",
        (false, true) => "LOCAL LAN",
        (false, false) => "STREAM",
    };

    let (st_txt, st_col) = if !acc.reaches_gateway {
        ("NO GATEWAY UPLINK".to_string(), [0.98f32, 0.65, 0.22, 1.0])
    } else if acc.speed >= 1.0 {
        (
            format!("ACTIVE · {}", scope_tag),
            if acc.has_wan {
                [0.25f32, 0.94, 0.72, 1.0]
            } else {
                [0.20f32, 0.86, 0.98, 1.0]
            },
        )
    } else {
        (
            format!("IDLE (0 B/s) · {}", scope_tag),
            [0.62f32, 0.70, 0.82, 1.0],
        )
    };
    node.set_readout_nth(0, "State:", st_txt, Some(st_col));

    let ratio = if acc.speed >= 1.0 {
        (acc.bytes as f32 / max_sys_bytes)
            .max((acc.speed as f32) / (1024.0 * 1024.0 * 2.0))
            .clamp(0.06, 1.0)
    } else {
        0.04
    };
    node.set_data_meter(
        format_speed(acc.speed),
        format_bytes(acc.bytes),
        ratio,
        Some(if acc.speed >= 1.0 {
            [0.80f32, 0.55, 0.98, 1.0]
        } else {
            idle_col
        }),
    );

    let (selected_wave, wave_mode) = match node.probe_config.wave_channel {
        ProbeWaveChannel::Combined => (&acc.wave, 0u8),
        ProbeWaveChannel::DownloadOnly => (&acc.down_wave, 1u8),
        ProbeWaveChannel::UploadOnly => (&acc.up_wave, 2u8),
    };
    let peak_spd = selected_wave.iter().copied().fold(0.0f32, f32::max) as f64;
    node.set_wave_detailed(&acc.wave, &acc.down_wave, &acc.up_wave, wave_mode);

    let hi_col = [0.88f32, 0.93, 0.99, 1.0];
    let sub_col = [0.64f32, 0.76, 0.90, 1.0];

    match node.probe_config.variant {
        ProbeVariant::BandwidthWave => {
            node.set_readout_nth(
                1,
                "Down / Up:",
                format!("▼ {}  ▲ {}", format_speed(acc.down_speed), format_speed(acc.up_speed)),
                Some([0.22f32, 0.92, 0.78, 1.0]),
            );
            node.set_readout_nth(
                2,
                "Peak / Scks:",
                format!("Peak {} · {} act/{} tot", format_speed(peak_spd), acc.active_sockets, acc.total_sockets),
                Some(sub_col),
            );
            node.set_readout_nth(
                3,
                "Top Flow:",
                if acc.top_app_line.is_empty() {
                    "No active app".to_string()
                } else {
                    acc.top_app_line.clone()
                },
                Some(hi_col),
            );
        }
        ProbeVariant::SplitInOut => {
            let tot_b = (acc.down_bytes + acc.up_bytes).max(1);
            let in_pct = ((acc.down_bytes as f64 / tot_b as f64) * 100.0).round() as u32;
            node.set_readout_nth(
                1,
                "IN (Down):",
                format!("{} ({})", format_speed(acc.down_speed), format_bytes(acc.down_bytes)),
                Some([0.16f32, 0.92, 0.78, 1.0]),
            );
            node.set_readout_nth(
                2,
                "OUT (Up):",
                format!("{} ({})", format_speed(acc.up_speed), format_bytes(acc.up_bytes)),
                Some([0.98f32, 0.48, 0.66, 1.0]),
            );
            node.set_readout_nth(
                3,
                "Share/Peak:",
                format!("IN {}% / OUT {}% · Peak {}", in_pct, 100u32.saturating_sub(in_pct), format_speed(peak_spd)),
                Some(sub_col),
            );
        }
        ProbeVariant::FlowEndpoints => {
            node.set_readout_nth(
                1,
                "Top App:",
                if acc.top_app_line.is_empty() {
                    "None".to_string()
                } else {
                    acc.top_app_line.clone()
                },
                Some(hi_col),
            );
            node.set_readout_nth(
                2,
                "Endpoint:",
                if acc.top_endpoint_line.is_empty() {
                    "No remote endpoint".to_string()
                } else {
                    acc.top_endpoint_line.clone()
                },
                Some([0.32f32, 0.90, 0.72, 1.0]),
            );
            node.set_readout_nth(
                3,
                "Protocols:",
                if acc.top_proto_line.is_empty() {
                    "None".to_string()
                } else {
                    acc.top_proto_line.clone()
                },
                Some(sub_col),
            );
        }
        ProbeVariant::SocketTelemetry => {
            node.set_readout_nth(
                1,
                "States:",
                format!(
                    "EST: {} · WAIT: {} · TOT: {}",
                    acc.active_sockets, acc.wait_sockets, acc.total_sockets
                ),
                Some([0.28f32, 0.92, 0.72, 1.0]),
            );
            node.set_readout_nth(
                2,
                "Transport:",
                format!("TCP: {} socks · UDP: {} socks", acc.tcp_sockets, acc.udp_sockets),
                Some(hi_col),
            );
            node.set_readout_nth(
                3,
                "Ports:",
                if acc.top_ports_line.is_empty() {
                    "None".to_string()
                } else {
                    acc.top_ports_line.clone()
                },
                Some(sub_col),
            );
        }
    }
}
