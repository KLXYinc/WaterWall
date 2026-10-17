use super::Graph;
use crate::gui::groups::AppGroupManager;
use crate::gui::nodes::{Item, Node, NodeKind};
use crate::net::{
    format_bytes, format_speed, is_remote_ip, resolve_pids_for_app_names, sync_ebpf_proxied_pids,
    terminate_single_socket, AppNetworkInfo, NetworkMonitor, NetworkSnapshot, UpstreamProxyConfig,
    UpstreamProxyKind, HISTORY_LEN,
};

#[derive(Clone)]
struct NodeFlowAccum {
    has_input: bool,
    reaches_gateway: bool,
    speed: f64,
    bytes: u64,
    wan_speed: f64,
    lan_speed: f64,
    wan_bytes: u64,
    lan_bytes: u64,
    wave: Vec<f32>,
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

            // Accumulate flow into visited nodes for WAN and LAN paths
            accumulate_trace(&mut node_accum, &wan_trace, !wan_blocked, true, wan_spd, wan_bytes, &combined_wave, wan_share as f32);
            accumulate_trace(&mut node_accum, &lan_trace, !lan_blocked, false, lan_spd, lan_bytes, &combined_wave, 1.0 - wan_share as f32);

            self.apply_trace_to_links(&wan_trace, wan_blocked, "WAN", wan_spd, wan_bytes, wan_socks, max_sys_bytes);
            self.apply_trace_to_links(&lan_trace, lan_blocked, "LAN", lan_spd, lan_bytes, lan_socks, max_sys_bytes);
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
        let all_proxied_pids = resolve_pids_for_app_names(&ebpf_proxied_names, &ebpf_proxied_pids);
        let (ebpf_ok, ebpf_msg) = sync_ebpf_proxied_pids(&all_proxied_pids);

        // 3. Update every non-group node strictly from its accumulated connected flow!
        self.update_node_telemetry(snap, monitor, &node_accum, max_sys_bytes, blackhole_all, ebpf_ok, &ebpf_msg);
    }

    #[allow(clippy::too_many_arguments)]
    fn update_node_telemetry(&mut self, snap: &NetworkSnapshot, monitor: &NetworkMonitor, node_accum: &[NodeFlowAccum], max_sys_bytes: f32, blackhole_all: bool, ebpf_ok: bool, ebpf_msg: &str) {
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
                            1 if !ports.is_empty() || !host.is_empty() => (format!("BLOCK {} {}", ports, host), [0.98f32, 0.78, 0.20, 1.0]),
                            0 if !ports.is_empty() || !host.is_empty() => (format!("ALLOW {} {}", ports, host), [0.25f32, 0.92, 0.68, 1.0]),
                            _ => (format!("PASS ({})", format_speed(acc.speed)), [0.25f32, 0.92, 0.68, 1.0]),
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
                        let (_, proto_name) = self.nodes[i].combo_selected("Proto:").unwrap_or((0, "WireGuard"));
                        let iface = self.nodes[i].text_input("Iface:").unwrap_or("wg0").trim().to_string();
                        let matched = snap.vpn_interfaces.iter().find(|v| v.name.eq_ignore_ascii_case(&iface));
                        let status_txt = match matched {
                            Some(v) if v.is_up => format!("UP: {} ({})", v.name, format_speed(acc.speed)),
                            _ => format!("{} [{}] · {}", proto_name, if iface.is_empty() { "wg0" } else { &iface }, format_speed(acc.speed)),
                        };
                        self.nodes[i].set_readout("Status:", status_txt, Some([0.20f32, 0.90, 0.78, 1.0]));
                    }
                }
                NodeKind::ProxyNode => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("Status:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else if !ebpf_ok {
                        self.nodes[i].set_readout(
                            "Status:",
                            ebpf_msg.to_string(),
                            Some([0.98f32, 0.72, 0.22, 1.0]),
                        );
                    } else {
                        let relayed = monitor.proxy_relay.relayed_connections();
                        let srv = self.nodes[i].text_input("Server:").unwrap_or("127.0.0.1:1080").trim().to_string();
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
                        self.nodes[i].set_readout("Status:", format!("CAP {:.0} KB/s ({})", cap, format_speed(acc.speed)), Some([0.98f32, 0.68, 0.22, 1.0]));
                    }
                }
                NodeKind::TrafficMonitor => {
                    if !acc.has_input {
                        self.nodes[i].set_readout("State:", "DISCONNECTED".to_string(), Some(idle_col));
                        self.nodes[i].set_data_meter("0 B/s".to_string(), "0 B".to_string(), 0.0, Some(idle_col));
                        self.nodes[i].set_wave(&flat_wave);
                    } else {
                        let (st, col) = if acc.reaches_gateway {
                            ("PROBING ACTIVE FLOW", [0.80f32, 0.55, 0.98, 1.0])
                        } else {
                            ("NO GATEWAY UPLINK", [0.98f32, 0.65, 0.22, 1.0])
                        };
                        let ratio = (acc.bytes as f32 / max_sys_bytes).max((acc.speed as f32) / (1024.0 * 1024.0 * 2.0)).clamp(0.05, 1.0);
                        self.nodes[i].set_readout("State:", st.to_string(), Some(col));
                        self.nodes[i].set_data_meter(format_speed(acc.speed), format_bytes(acc.bytes), ratio, Some(col));
                        self.nodes[i].set_wave(&acc.wave);
                    }
                }
                NodeKind::InternetGateway => {
                    if !acc.has_input || blackhole_all {
                        self.nodes[i].set_data_meter("0 B/s".to_string(), "0 B".to_string(), 0.0, Some(idle_col));
                        self.nodes[i].set_readout(
                            "WAN In:",
                            if blackhole_all { "BLACKHOLE DROP".to_string() } else { "DISCONNECTED".to_string() },
                            Some(if blackhole_all { [0.95f32, 0.30, 0.30, 1.0] } else { idle_col }),
                        );
                        self.nodes[i].set_readout("LAN In:", "DISCONNECTED".to_string(), Some(idle_col));
                    } else {
                        let ratio = (acc.bytes as f32 / max_sys_bytes).max((acc.speed as f32) / (1024.0 * 1024.0 * 2.0)).clamp(0.06, 1.0);
                        self.nodes[i].set_data_meter(format_speed(acc.speed), format_bytes(acc.bytes), ratio, None);
                        self.nodes[i].set_readout("WAN In:", format!("{} ({})", format_speed(acc.wan_speed), format_bytes(acc.wan_bytes)), None);
                        self.nodes[i].set_readout("LAN In:", format!("{} ({})", format_speed(acc.lan_speed), format_bytes(acc.lan_bytes)), None);
                    }
                }
                _ => {}
            }
        }
    }

    fn trace_exit_path(
        &self,
        start_node_idx: usize,
        exit_slot: usize,
        member_apps: &[&AppNetworkInfo],
        blackhole_all: bool,
    ) -> ExitTraceResult {
        let find_node_by_pin = |nodes: &[Node], target_pin: i32| -> Option<usize> {
            nodes.iter().position(|n| n.items.iter().any(|it| matches!(it, Item::Pin(p) if p.id == target_pin)))
        };

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
            let Some(next_idx) = find_node_by_pin(&self.nodes, next_in_pin) else { break };
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

    #[allow(clippy::too_many_arguments)]
    fn apply_trace_to_links(
        &mut self,
        trace: &ExitTraceResult,
        is_blocked: bool,
        scope_prefix: &str,
        spd: f64,
        bytes: u64,
        socks: usize,
        max_sys_bytes: f32,
    ) {
        let speed_intensity = ((spd as f32) / (1024.0 * 512.0)).clamp(0.0, 0.72);
        let vol_intensity = ((bytes as f32) / max_sys_bytes).clamp(0.10, 0.38);
        let calc_intensity = if is_blocked { -1.0 } else { (speed_intensity + vol_intensity).clamp(0.18, 1.0) };

        let badge = if is_blocked {
            format!("{} BLOCKED", scope_prefix)
        } else if let Some(tag) = &trace.route_tag {
            format!("{}: {} | {}", scope_prefix, tag, format_bytes(bytes))
        } else if spd > 0.0 {
            format!("{}: {} | {}", scope_prefix, format_speed(spd), format_bytes(bytes))
        } else {
            format!("{}: {} ({} conns)", scope_prefix, format_bytes(bytes), socks)
        };

        for (hop, &l_idx) in trace.visited_links.iter().enumerate() {
            if calc_intensity < 0.0 {
                self.links[l_idx].flow_intensity = -1.0;
                self.links[l_idx].label = format!("{} BLOCKED", scope_prefix);
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

#[allow(clippy::too_many_arguments)]
fn accumulate_trace(
    node_accum: &mut [NodeFlowAccum],
    trace: &ExitTraceResult,
    active_flow: bool,
    is_wan: bool,
    spd: f64,
    bytes: u64,
    wave: &[f32],
    share: f32,
) {
    for &n_idx in &trace.visited_nodes {
        let acc = &mut node_accum[n_idx];
        acc.has_input = true;
        acc.reaches_gateway |= trace.reaches_gateway && active_flow;
        if active_flow {
            let eff_spd = trace.throttled_kbs.map_or(spd, |kbs| spd.min(kbs as f64 * 1024.0));
            acc.speed += eff_spd;
            acc.bytes += bytes;
            if is_wan {
                acc.wan_speed += eff_spd;
                acc.wan_bytes += bytes;
            } else {
                acc.lan_speed += eff_spd;
                acc.lan_bytes += bytes;
            }
            for (k, &v) in wave.iter().enumerate().take(HISTORY_LEN) {
                acc.wave[k] += v * share;
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
