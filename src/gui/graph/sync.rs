use super::Graph;
use crate::gui::groups::AppGroupManager;
use crate::gui::nodes::NodeKind;
use crate::net::{
    format_bytes, format_speed, is_remote_ip, sync_ebpf_for_apps, terminate_single_socket,
    AppNetworkInfo, NetworkMonitor, NetworkSnapshot, UpstreamProxyConfig, UpstreamProxyKind,
    HISTORY_LEN,
};

#[derive(Clone)]
pub(super) struct NodeFlowAccum {
    pub(super) has_input: bool,
    pub(super) reaches_gateway: bool,
    pub(super) speed: f64,
    pub(super) bytes: u64,
    pub(super) wan_speed: f64,
    pub(super) lan_speed: f64,
    pub(super) wan_bytes: u64,
    pub(super) lan_bytes: u64,
    pub(super) wave: Vec<f32>,
}

impl Default for NodeFlowAccum {
    fn default() -> Self {
        Self { has_input: false, reaches_gateway: false, speed: 0.0, bytes: 0, wan_speed: 0.0, lan_speed: 0.0, wan_bytes: 0, lan_bytes: 0, wave: vec![0.0; HISTORY_LEN] }
    }
}

struct ExitTraceResult {
    reaches_gateway: bool,
    blocked: bool,
    proxied: bool,
    proxy_node_idx: Option<usize>,
    throttled_kbs: Option<f32>,
    route_tag: Option<String>,
    visited_nodes: Vec<usize>,
    visited_links: Vec<usize>,
}

struct TraceScopeMetrics<'a> {
    scope_prefix: &'static str,
    is_wan: bool,
    blocked: bool,
    spd: f64,
    bytes: u64,
    socks: usize,
    share: f32,
    wave: &'a [f32],
    max_sys_bytes: f32,
}

impl Graph {
    /// Synchronizes active AppGroup nodes, traces actual connected rope paths for Remote WAN (exit 0)
    /// and Local LAN (exit 1), and updates every node strictly from the flows passing through it.
    pub fn sync_with_monitor(
        &mut self,
        snap: &NetworkSnapshot,
        groups: &AppGroupManager,
        monitor: &NetworkMonitor,
    ) {
        for (order_idx, gid) in groups.active_group_ids().into_iter().enumerate() {
            if let Some(grp) = groups.get_group(gid) {
                self.push_group_node(gid, &grp.name, grp.color, [35.0, 55.0 + order_idx as f32 * 215.0]);
            }
        }

        let max_sys_bytes = (snap.session_total_download + snap.session_total_upload).max(1024 * 1024) as f32;
        let blackhole_all = self
            .nodes
            .iter()
            .find(|n| n.kind == NodeKind::InternetGateway)
            .and_then(|n| n.checkbox("Blackhole Drop All"))
            .unwrap_or(false);

        for link in &mut self.links {
            link.label.clear();
        }

        let mut node_accum: Vec<NodeFlowAccum> = vec![NodeFlowAccum::default(); self.nodes.len()];
        let mut ebpf_proxied_pids: Vec<u32> = Vec::new();
        let mut ebpf_proxied_names: Vec<String> = Vec::new();
        let mut active_proxy_node_idx: Option<usize> = None;

        // 1. Evaluate each AppGroup node and trace Exit 0 (Remote WAN) & Exit 1 (Local LAN)
        for i in 0..self.nodes.len() {
            if self.nodes[i].kind != NodeKind::AppGroup {
                continue;
            }
            let gid = self.nodes[i].bound_group_id.unwrap_or(0);
            let group_color = self.nodes[i].accent;
            let member_apps = groups.apps_in_group(gid, &snap.apps);

            let group_spd: f64 = member_apps.iter().map(|a| a.download_speed + a.upload_speed).sum();
            let group_bytes: u64 = member_apps.iter().map(|a| a.total_downloaded + a.total_uploaded).sum();

            let (mut wan_socks, mut lan_socks) = (0usize, 0usize);
            for app in &member_apps {
                for c in &app.connections {
                    if c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip()) {
                        wan_socks += 1;
                    } else {
                        lan_socks += 1;
                    }
                }
            }

            let mut combined_wave = vec![0.0f32; HISTORY_LEN];
            for app in &member_apps {
                for (idx, &v) in app.download_history.iter().enumerate().take(HISTORY_LEN) {
                    combined_wave[idx] += v;
                }
                for (idx, &v) in app.upload_history.iter().enumerate().take(HISTORY_LEN) {
                    combined_wave[idx] += v;
                }
            }

            let btn_label = match member_apps.len() {
                0 => "Show / Add Apps (0)".to_string(),
                1 => format!("Apps (1): {}", member_apps[0].name),
                n => format!("Show / Edit Apps ({})", n),
            };

            let fill_ratio = (group_bytes as f32 / max_sys_bytes)
                .max((group_spd as f32) / (1024.0 * 1024.0 * 2.0))
                .clamp(0.05, 1.0);
            self.nodes[i].set_data_meter(format_speed(group_spd), format_bytes(group_bytes), fill_ratio, Some(group_color));
            self.nodes[i].set_group_apps_label(btn_label);
            self.nodes[i].set_readout("Sockets:", format!("{} WAN / {} LAN", wan_socks, lan_socks), None);
            self.nodes[i].set_wave(&combined_wave);

            let tot_socks = (wan_socks + lan_socks).max(1) as f64;
            let wan_share = if wan_socks > 0 && lan_socks > 0 {
                (wan_socks as f64 / tot_socks).clamp(0.15, 0.85)
            } else if wan_socks > 0 {
                1.0
            } else {
                0.0
            };
            let wan_bytes = (group_bytes as f64 * wan_share) as u64;
            let lan_bytes = group_bytes.saturating_sub(wan_bytes);
            let (wan_spd, lan_spd) = (group_spd * wan_share, group_spd * (1.0 - wan_share));

            let wan_trace = self.trace_exit_path(i, 0, &member_apps, blackhole_all);
            let lan_trace = self.trace_exit_path(i, 1, &member_apps, blackhole_all);

            let wan_blocked = !wan_trace.reaches_gateway || wan_trace.blocked;
            let lan_blocked = !lan_trace.reaches_gateway || lan_trace.blocked;

            if wan_trace.proxied && !wan_blocked && wan_trace.proxy_node_idx.is_some() {
                active_proxy_node_idx = wan_trace.proxy_node_idx;
                for (assigned_app, &assigned_gid) in &groups.app_to_group {
                    if assigned_gid == gid {
                        ebpf_proxied_names.push(assigned_app.clone());
                    }
                }
                for app in &member_apps {
                    ebpf_proxied_pids.extend(app.pids.iter().copied());
                    ebpf_proxied_names.push(app.name.clone());
                }
            }

            if wan_blocked && lan_blocked {
                for app in &member_apps {
                    monitor.set_app_blocked_by_name(&app.name, true);
                }
            } else {
                for app in &member_apps {
                    monitor.set_app_blocked_by_name(&app.name, false);
                    monitor.set_app_proxied_by_name(&app.name, wan_trace.proxied);
                }
                if wan_blocked {
                    drop_scope_sockets(&member_apps, true);
                }
                if lan_blocked {
                    drop_scope_sockets(&member_apps, false);
                }
            }

            let wan_metrics = TraceScopeMetrics {
                scope_prefix: "WAN",
                is_wan: true,
                blocked: wan_blocked,
                spd: wan_spd,
                bytes: wan_bytes,
                socks: wan_socks,
                share: wan_share as f32,
                wave: &combined_wave,
                max_sys_bytes,
            };
            let lan_metrics = TraceScopeMetrics {
                scope_prefix: "LAN",
                is_wan: false,
                blocked: lan_blocked,
                spd: lan_spd,
                bytes: lan_bytes,
                socks: lan_socks,
                share: 1.0 - wan_share as f32,
                wave: &combined_wave,
                max_sys_bytes,
            };

            accumulate_trace(&mut node_accum, &wan_trace, &wan_metrics);
            accumulate_trace(&mut node_accum, &lan_trace, &lan_metrics);

            self.apply_trace_to_links(&wan_trace, &wan_metrics);
            self.apply_trace_to_links(&lan_trace, &lan_metrics);
        }

        // 2. Sync upstream Proxy config to LocalProxyRelay & attach eBPF cgroup/connect4 to proxied PIDs
        if let Some(p_idx) = active_proxy_node_idx {
            let (type_idx, _) = self.nodes[p_idx].combo_selected("Type:").unwrap_or((1, ""));
            let srv = self.nodes[p_idx].text_input("Server:").unwrap_or("127.0.0.1:1080").trim().to_string();
            let usr = self.nodes[p_idx].text_input("User:").unwrap_or("").trim().to_string();
            let pwd = self.nodes[p_idx].text_input("Pass:").unwrap_or("").trim().to_string();
            let kind = if type_idx == 1 { UpstreamProxyKind::HttpConnect } else { UpstreamProxyKind::Socks5 };
            monitor.proxy_relay.update_config(UpstreamProxyConfig { enabled: true, kind, server: srv, username: usr, password: pwd });
        } else {
            monitor.proxy_relay.update_config(UpstreamProxyConfig::default());
        }
        let ebpf_state = sync_ebpf_for_apps(&ebpf_proxied_names, &ebpf_proxied_pids);

        // 3. Update every non-group node strictly from its accumulated connected flow!
        self.update_node_telemetry(snap, monitor, &node_accum, max_sys_bytes, blackhole_all, ebpf_state);
    }

    fn trace_exit_path(
        &self,
        start_node_idx: usize,
        exit_slot: usize,
        member_apps: &[&AppNetworkInfo],
        blackhole_all: bool,
    ) -> ExitTraceResult {
        let mut res = ExitTraceResult {
            reaches_gateway: false,
            blocked: blackhole_all,
            proxied: false,
            proxy_node_idx: None,
            throttled_kbs: None,
            route_tag: None,
            visited_nodes: Vec::new(),
            visited_links: Vec::new(),
        };

        let mut cur_node_idx = start_node_idx;
        for hop in 0..7 {
            let out_pin = if hop == 0 {
                self.nodes[cur_node_idx].pin_id_nth(false, exit_slot)
            } else {
                self.nodes[cur_node_idx].pin_id(false)
            };
            let Some(pin) = out_pin else { break };
            let Some(link_idx) = self.links.iter().position(|l| l.from == pin) else { break };

            res.visited_links.push(link_idx);
            let next_in_pin = self.links[link_idx].to;
            let Some(next_idx) = self.find_node_by_pin(next_in_pin) else { break };
            res.visited_nodes.push(next_idx);

            match self.nodes[next_idx].kind {
                NodeKind::BlockNode => {
                    res.blocked = true;
                    break;
                }
                NodeKind::FilterNode => {
                    let (mode_idx, _) = self.nodes[next_idx].combo_selected("Mode:").unwrap_or((0, ""));
                    let ports = self.nodes[next_idx].text_input("Ports:").unwrap_or("");
                    let host = self.nodes[next_idx].text_input("Host:").unwrap_or("");
                    if mode_idx == 2 {
                        res.blocked = true;
                    } else {
                        drop_matching_sockets(member_apps, mode_idx, exit_slot == 0, ports, host);
                    }
                }
                NodeKind::VpnNode if exit_slot == 0 => {
                    res.proxied = true;
                    let iface = self.nodes[next_idx].text_input("Iface:").unwrap_or("wg0").trim();
                    res.route_tag = Some(format!("VPN {}", if iface.is_empty() { "wg0" } else { iface }));
                }
                NodeKind::ProxyNode if exit_slot == 0 => {
                    res.proxied = true;
                    res.proxy_node_idx = Some(next_idx);
                    res.route_tag = Some(String::from("Proxy"));
                }
                NodeKind::RateLimiter => {
                    let cap = self.nodes[next_idx].slider("Max Speed (KB/s)").unwrap_or(4096.0);
                    res.throttled_kbs = Some(res.throttled_kbs.map_or(cap, |prev| prev.min(cap)));
                }
                NodeKind::InternetGateway => {
                    res.reaches_gateway = true;
                    if self.nodes[next_idx].checkbox("Blackhole Drop All").unwrap_or(false) {
                        res.blocked = true;
                    }
                    break;
                }
                _ => {}
            }
            cur_node_idx = next_idx;
        }
        res
    }

    fn apply_trace_to_links(&mut self, trace: &ExitTraceResult, m: &TraceScopeMetrics<'_>) {
        let speed_intensity = ((m.spd as f32) / (1024.0 * 512.0)).clamp(0.0, 0.72);
        let vol_intensity = ((m.bytes as f32) / m.max_sys_bytes).clamp(0.10, 0.38);
        let calc_intensity = if m.blocked {
            -1.0
        } else {
            (speed_intensity + vol_intensity).clamp(0.18, 1.0)
        };

        let badge = if m.blocked {
            format!("{} BLOCKED", m.scope_prefix)
        } else if let Some(tag) = &trace.route_tag {
            format!("{}: {} | {}", m.scope_prefix, tag, format_bytes(m.bytes))
        } else if m.spd > 0.0 {
            format!(
                "{}: {} | {}",
                m.scope_prefix,
                format_speed(m.spd),
                format_bytes(m.bytes)
            )
        } else {
            format!(
                "{}: {} ({} conns)",
                m.scope_prefix,
                format_bytes(m.bytes),
                m.socks
            )
        };

        for (hop, &l_idx) in trace.visited_links.iter().enumerate() {
            if calc_intensity < 0.0 {
                self.links[l_idx].flow_intensity = -1.0;
                self.links[l_idx].label = format!("{} BLOCKED", m.scope_prefix);
            } else {
                let prev = self.links[l_idx].flow_intensity.max(0.15);
                self.links[l_idx].flow_intensity = prev * 0.88 + calc_intensity * 0.12;
                if hop == 0 || self.links[l_idx].label.is_empty() {
                    self.links[l_idx].label = badge.clone();
                }
            }
        }
    }
}

fn accumulate_trace(
    node_accum: &mut [NodeFlowAccum],
    trace: &ExitTraceResult,
    m: &TraceScopeMetrics<'_>,
) {
    let active_flow = !m.blocked;
    for &n_idx in &trace.visited_nodes {
        let acc = &mut node_accum[n_idx];
        acc.has_input = true;
        acc.reaches_gateway |= trace.reaches_gateway && active_flow;
        if active_flow {
            let eff_spd = trace.throttled_kbs.map_or(m.spd, |kbs| m.spd.min(kbs as f64 * 1024.0));
            acc.speed += eff_spd;
            acc.bytes += m.bytes;
            if m.is_wan {
                acc.wan_speed += eff_spd;
                acc.wan_bytes += m.bytes;
            } else {
                acc.lan_speed += eff_spd;
                acc.lan_bytes += m.bytes;
            }
            for (k, &v) in m.wave.iter().enumerate().take(HISTORY_LEN) {
                acc.wave[k] += v * m.share;
            }
        }
    }
}

fn drop_scope_sockets(apps: &[&AppNetworkInfo], drop_remote_wan: bool) {
    for c in apps.iter().flat_map(|a| &a.connections) {
        if c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip()) == drop_remote_wan {
            terminate_single_socket(&c.remote_addr);
        }
    }
}

fn drop_matching_sockets(apps: &[&AppNetworkInfo], mode_idx: usize, wan_scope: bool, ports_filter: &str, host_filter: &str) {
    let parsed_ports: Vec<u16> = ports_filter.split(|c: char| c == ',' || c.is_whitespace()).filter_map(|s| s.trim().parse().ok()).collect();
    let host_q = host_filter.trim().to_lowercase();
    if parsed_ports.is_empty() && host_q.is_empty() {
        return;
    }
    for conn in apps.iter().flat_map(|a| &a.connections) {
        let rport = conn.remote_addr.port();
        if rport == 0 || is_remote_ip(&conn.remote_addr.ip()) != wan_scope {
            continue;
        }
        let port_ok = parsed_ports.is_empty() || parsed_ports.contains(&rport);
        let host_ok = host_q.is_empty() || conn.remote_addr.ip().to_string().contains(&host_q) || conn.domain.as_ref().is_some_and(|d| d.to_lowercase().contains(&host_q));
        if (mode_idx == 0 && !(port_ok && host_ok)) || (mode_idx == 1 && port_ok && host_ok) {
            terminate_single_socket(&conn.remote_addr);
        }
    }
}
