use std::collections::HashMap;

use crate::net::{
    classify_ip_location_with_domain, classify_traffic_type, format_speed, is_remote_ip,
    AppNetworkInfo, Protocol, SocketState, HISTORY_LEN,
};
use crate::utils::truncate_str;

#[derive(Clone)]
pub(super) struct NodeFlowAccum {
    pub(super) has_input: bool,
    pub(super) reaches_gateway: bool,
    pub(super) has_wan: bool,
    pub(super) has_lan: bool,
    pub(super) speed: f64,
    pub(super) down_speed: f64,
    pub(super) up_speed: f64,
    pub(super) bytes: u64,
    pub(super) down_bytes: u64,
    pub(super) up_bytes: u64,
    pub(super) wan_speed: f64,
    pub(super) lan_speed: f64,
    pub(super) wan_bytes: u64,
    pub(super) lan_bytes: u64,
    pub(super) total_sockets: usize,
    pub(super) active_sockets: usize,
    pub(super) tcp_sockets: usize,
    pub(super) udp_sockets: usize,
    pub(super) wait_sockets: usize,
    pub(super) top_app_line: String,
    pub(super) top_endpoint_line: String,
    pub(super) top_proto_line: String,
    pub(super) top_ports_line: String,
    pub(super) wave: Vec<f32>,
    pub(super) down_wave: Vec<f32>,
    pub(super) up_wave: Vec<f32>,
}

impl Default for NodeFlowAccum {
    fn default() -> Self {
        Self {
            has_input: false,
            reaches_gateway: false,
            has_wan: false,
            has_lan: false,
            speed: 0.0,
            down_speed: 0.0,
            up_speed: 0.0,
            bytes: 0,
            down_bytes: 0,
            up_bytes: 0,
            wan_speed: 0.0,
            lan_speed: 0.0,
            wan_bytes: 0,
            lan_bytes: 0,
            total_sockets: 0,
            active_sockets: 0,
            tcp_sockets: 0,
            udp_sockets: 0,
            wait_sockets: 0,
            top_app_line: String::new(),
            top_endpoint_line: String::new(),
            top_proto_line: String::new(),
            top_ports_line: String::new(),
            wave: vec![0.0; HISTORY_LEN],
            down_wave: vec![0.0; HISTORY_LEN],
            up_wave: vec![0.0; HISTORY_LEN],
        }
    }
}

#[derive(Default)]
pub(super) struct ScopeFlowData {
    pub(super) down_spd: f64,
    pub(super) up_spd: f64,
    pub(super) pkt_rate: f64,
    pub(super) down_bytes: u64,
    pub(super) up_bytes: u64,
    pub(super) total_pkts: u64,
    pub(super) total_socks: usize,
    pub(super) active_socks: usize,
    pub(super) tcp_socks: usize,
    pub(super) udp_socks: usize,
    pub(super) wait_socks: usize,
    pub(super) top_app: Option<(String, f64, usize)>,
    pub(super) top_endpoint: String,
    pub(super) top_proto: String,
    pub(super) top_ports: String,
    pub(super) down_wave: Vec<f32>,
    pub(super) up_wave: Vec<f32>,
}

impl ScopeFlowData {
    pub(super) fn new() -> Self {
        Self {
            down_wave: vec![0.0; HISTORY_LEN],
            up_wave: vec![0.0; HISTORY_LEN],
            ..Self::default()
        }
    }

    pub(super) fn total_spd(&self) -> f64 {
        self.down_spd + self.up_spd
    }

    pub(super) fn total_bytes(&self) -> u64 {
        self.down_bytes + self.up_bytes
    }
}

/// Evaluates each application in `member_apps` individually so localhost/LAN apps never leak their
/// traffic or bandwidth into the Remote WAN path (and vice versa).
pub(super) fn compute_per_app_scope_flows(
    member_apps: &[&AppNetworkInfo],
) -> (ScopeFlowData, ScopeFlowData) {
    let mut wan = ScopeFlowData::new();
    let mut lan = ScopeFlowData::new();
    let mut wan_protos: HashMap<&'static str, usize> = HashMap::new();
    let mut lan_protos: HashMap<&'static str, usize> = HashMap::new();
    let mut wan_ports: Vec<u16> = Vec::new();
    let mut lan_ports: Vec<u16> = Vec::new();

    for app in member_apps {
        let (mut app_wan_tot, mut app_wan_act) = (0usize, 0usize);
        let (mut app_lan_tot, mut app_lan_act) = (0usize, 0usize);

        for c in &app.connections {
            let is_wan = c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip());
            let is_act = c.state.is_active();
            let is_wait = matches!(
                c.state,
                SocketState::TimeWait
                    | SocketState::CloseWait
                    | SocketState::FinWait1
                    | SocketState::FinWait2
            );
            let (_, proto_code, _) =
                classify_traffic_type(c.protocol.as_str(), &c.local_addr, &c.remote_addr);
            let port = if c.remote_addr.port() != 0 {
                c.remote_addr.port()
            } else {
                c.local_addr.port()
            };

            let target = if is_wan {
                app_wan_tot += 1;
                if is_act {
                    app_wan_act += 1;
                }
                *wan_protos.entry(proto_code).or_insert(0) += 1;
                if port != 0 && !wan_ports.contains(&port) && wan_ports.len() < 4 {
                    wan_ports.push(port);
                }
                if wan.top_endpoint.is_empty() || is_act {
                    let loc =
                        classify_ip_location_with_domain(&c.remote_addr.ip(), c.domain.as_deref());
                    let host_lbl = c.domain.as_deref().unwrap_or("");
                    wan.top_endpoint = if !host_lbl.is_empty() {
                        format!(
                            "{} [{}]",
                            truncate_str(host_lbl, 16),
                            loc.country_code.code()
                        )
                    } else {
                        format!(
                            "{}:{} [{}]",
                            c.remote_addr.ip(),
                            c.remote_addr.port(),
                            loc.country_code.code()
                        )
                    };
                }
                &mut wan
            } else {
                app_lan_tot += 1;
                if is_act {
                    app_lan_act += 1;
                }
                *lan_protos.entry(proto_code).or_insert(0) += 1;
                if port != 0 && !lan_ports.contains(&port) && lan_ports.len() < 4 {
                    lan_ports.push(port);
                }
                if lan.top_endpoint.is_empty() || is_act {
                    lan.top_endpoint = if c.remote_addr.port() != 0 {
                        format!("{}:{} [LAN]", c.remote_addr.ip(), c.remote_addr.port())
                    } else {
                        format!("Listen :{} [LAN]", c.local_addr.port())
                    };
                }
                &mut lan
            };

            target.total_socks += 1;
            if is_act {
                target.active_socks += 1;
            }
            if is_wait {
                target.wait_socks += 1;
            }
            match c.protocol {
                Protocol::Tcp => target.tcp_socks += 1,
                Protocol::Udp => target.udp_socks += 1,
            }
        }

        let wan_ratio = if app_wan_tot == 0 {
            0.0
        } else if app_lan_tot == 0 {
            1.0
        } else if app_wan_act > 0 || app_lan_act > 0 {
            app_wan_act as f64 / (app_wan_act + app_lan_act) as f64
        } else {
            app_wan_tot as f64 / (app_wan_tot + app_lan_tot) as f64
        };
        let lan_ratio = 1.0 - wan_ratio;

        if wan_ratio > 0.0 {
            add_app_to_scope(&mut wan, app, wan_ratio, app_wan_tot);
        }
        if lan_ratio > 0.0 {
            add_app_to_scope(&mut lan, app, lan_ratio, app_lan_tot);
        }
    }

    wan.top_proto = format_proto_map(&wan_protos);
    lan.top_proto = format_proto_map(&lan_protos);
    wan.top_ports = format_port_list(&wan_ports);
    lan.top_ports = format_port_list(&lan_ports);
    (wan, lan)
}

fn add_app_to_scope(
    scope: &mut ScopeFlowData,
    app: &AppNetworkInfo,
    ratio: f64,
    app_socks: usize,
) {
    let d_spd = app.download_speed * ratio;
    let u_spd = app.upload_speed * ratio;
    scope.down_spd += d_spd;
    scope.up_spd += u_spd;
    scope.pkt_rate += app.packet_rate * ratio;
    scope.down_bytes += (app.total_downloaded as f64 * ratio) as u64;
    scope.up_bytes += (app.total_uploaded as f64 * ratio) as u64;
    scope.total_pkts += (app.total_packets as f64 * ratio) as u64;
    for (dst, &v) in scope.down_wave.iter_mut().zip(app.download_history.iter()) {
        *dst += v * ratio as f32;
    }
    for (dst, &v) in scope.up_wave.iter_mut().zip(app.upload_history.iter()) {
        *dst += v * ratio as f32;
    }
    let app_spd = d_spd + u_spd;
    if scope
        .top_app
        .as_ref()
        .is_none_or(|(_, best_s, _)| app_spd >= *best_s)
    {
        scope.top_app = Some((app.name.clone(), app_spd, app_socks));
    }
}

fn format_proto_map(map: &HashMap<&'static str, usize>) -> String {
    let mut vec: Vec<(&'static str, usize)> = map.iter().map(|(&k, &v)| (k, v)).collect();
    vec.sort_by_key(|b| std::cmp::Reverse(b.1));
    if vec.is_empty() {
        return String::from("None");
    }
    vec.into_iter()
        .take(3)
        .map(|(k, n)| format!("{} ({})", k, n))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_port_list(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::from("None");
    }
    ports
        .iter()
        .take(4)
        .map(|p| format!(":{}", p))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn accumulate_trace(
    node_accum: &mut [NodeFlowAccum],
    visited_nodes: &[usize],
    reaches_gateway: bool,
    throttled_kbs: Option<f32>,
    flow: &ScopeFlowData,
    is_wan: bool,
    active_flow: bool,
) {
    let raw_spd = flow.total_spd();
    let eff_spd = throttled_kbs.map_or(raw_spd, |kbs| raw_spd.min(kbs as f64 * 1024.0));
    let scale = if raw_spd > 0.0 { eff_spd / raw_spd } else { 1.0 };

    for &n_idx in visited_nodes {
        let acc = &mut node_accum[n_idx];
        acc.has_input = true;
        acc.reaches_gateway |= reaches_gateway && active_flow;
        if is_wan {
            acc.has_wan = true;
        } else {
            acc.has_lan = true;
        }
        if active_flow {
            acc.speed += eff_spd;
            acc.down_speed += flow.down_spd * scale;
            acc.up_speed += flow.up_spd * scale;
            acc.bytes += flow.total_bytes();
            acc.down_bytes += flow.down_bytes;
            acc.up_bytes += flow.up_bytes;
            if is_wan {
                acc.wan_speed += eff_spd;
                acc.wan_bytes += flow.total_bytes();
            } else {
                acc.lan_speed += eff_spd;
                acc.lan_bytes += flow.total_bytes();
            }
            acc.total_sockets += flow.total_socks;
            acc.active_sockets += flow.active_socks;
            acc.tcp_sockets += flow.tcp_socks;
            acc.udp_sockets += flow.udp_socks;
            acc.wait_sockets += flow.wait_socks;

            if let Some((app_name, app_spd, app_socks)) = &flow.top_app {
                if acc.top_app_line.is_empty() || *app_spd > 0.0 {
                    acc.top_app_line = format!(
                        "{} · {} ({}s)",
                        truncate_str(app_name, 12),
                        format_speed(*app_spd),
                        app_socks
                    );
                }
            }
            if !flow.top_endpoint.is_empty() {
                acc.top_endpoint_line = flow.top_endpoint.clone();
            }
            if !flow.top_proto.is_empty() && flow.top_proto != "None" {
                acc.top_proto_line = flow.top_proto.clone();
            }
            if !flow.top_ports.is_empty() && flow.top_ports != "None" {
                acc.top_ports_line = flow.top_ports.clone();
            }

            for k in 0..HISTORY_LEN {
                acc.down_wave[k] += flow.down_wave[k];
                acc.up_wave[k] += flow.up_wave[k];
                acc.wave[k] += flow.down_wave[k] + flow.up_wave[k];
            }
        }
    }
}
