use super::flow_calc::{
    accumulate_trace, compute_per_app_scope_flows, NodeFlowAccum, ScopeFlowData,
};
use super::Graph;
use crate::gui::groups::AppGroupManager;
use crate::gui::nodes::{Item, Link, Node, NodeKind};
use crate::net::{
    format_bytes, format_speed, is_remote_ip, sync_ebpf_for_apps, terminate_single_socket,
    AppNetworkInfo, NetworkMonitor, NetworkSnapshot, UpstreamProxyConfig, UpstreamProxyKind,
    HISTORY_LEN,
};

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
    /// Synchronizes active AppGroup nodes, updates visual telemetry on the canvas from `self.nodes`
    /// and `self.links` (without applying unsaved network changes), and enforces actual network
    /// rules strictly from `self.committed_nodes`, `self.committed_links`, and `self.committed_groups`.
    pub fn sync_with_monitor(
        &mut self,
        snap: &NetworkSnapshot,
        groups: &AppGroupManager,
        monitor: &NetworkMonitor,
    ) {
        let was_clean = !self.has_unsaved_changes(groups);
        let prev_node_count = self.nodes.len();
        for (order_idx, gid) in groups.active_group_ids().into_iter().enumerate() {
            if let Some(grp) = groups.get_group(gid) {
                self.push_group_node(
                    gid,
                    &grp.name,
                    grp.color,
                    [35.0, 55.0 + order_idx as f32 * 215.0],
                );
            }
        }
        if was_clean && self.nodes.len() == prev_node_count {
            self.committed_sig = self.compute_policy_sig(groups);
        }

        let max_sys_bytes =
            (snap.session_total_download + snap.session_total_upload).max(1024 * 1024) as f32;
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

        // 1. Visual Canvas Pass (previews ropes, meters, waveforms & probes WITHOUT enforcing unsaved network rules)
        for i in 0..self.nodes.len() {
            if self.nodes[i].kind != NodeKind::AppGroup {
                continue;
            }
            let gid = self.nodes[i].bound_group_id.unwrap_or(0);
            let group_color = self.nodes[i].accent;
            let member_apps = groups.apps_in_group(gid, &snap.apps);

            let (wan_flow, lan_flow) = compute_per_app_scope_flows(&member_apps);
            let group_spd = wan_flow.total_spd() + lan_flow.total_spd();
            let group_bytes = wan_flow.total_bytes() + lan_flow.total_bytes();

            let down_wave: Vec<f32> = (0..HISTORY_LEN)
                .map(|k| wan_flow.down_wave[k] + lan_flow.down_wave[k])
                .collect();
            let up_wave: Vec<f32> = (0..HISTORY_LEN)
                .map(|k| wan_flow.up_wave[k] + lan_flow.up_wave[k])
                .collect();
            let combined_wave: Vec<f32> = (0..HISTORY_LEN)
                .map(|k| down_wave[k] + up_wave[k])
                .collect();

            let btn_label = match member_apps.len() {
                0 => "Show / Add Apps (0)".to_string(),
                1 => format!("Apps (1): {}", member_apps[0].name),
                n => format!("Show / Edit Apps ({})", n),
            };

            let fill_ratio = (group_bytes as f32 / max_sys_bytes)
                .max((group_spd as f32) / (1024.0 * 1024.0 * 2.0))
                .clamp(0.05, 1.0);
            self.nodes[i].set_data_meter(
                format_speed(group_spd),
                format_bytes(group_bytes),
                fill_ratio,
                Some(group_color),
            );
            self.nodes[i].set_group_apps_label(btn_label);
            self.nodes[i].set_readout(
                "Sockets:",
                format!("{} WAN / {} LAN", wan_flow.total_socks, lan_flow.total_socks),
                None,
            );
            self.nodes[i].set_wave_detailed(&combined_wave, &down_wave, &up_wave, 0);

            let wan_trace = trace_exit_path_on(
                &self.nodes,
                &self.links,
                i,
                0,
                &member_apps,
                blackhole_all,
                false,
            );
            let lan_trace = trace_exit_path_on(
                &self.nodes,
                &self.links,
                i,
                1,
                &member_apps,
                blackhole_all,
                false,
            );

            let wan_blocked = !wan_trace.reaches_gateway || wan_trace.blocked;
            let lan_blocked = !lan_trace.reaches_gateway || lan_trace.blocked;

            accumulate_trace(
                &mut node_accum,
                &wan_trace.visited_nodes,
                wan_trace.reaches_gateway,
                wan_trace.throttled_kbs,
                &wan_flow,
                true,
                !wan_blocked,
            );
            accumulate_trace(
                &mut node_accum,
                &lan_trace.visited_nodes,
                lan_trace.reaches_gateway,
                lan_trace.throttled_kbs,
                &lan_flow,
                false,
                !lan_blocked,
            );

            self.apply_trace_to_links(&wan_trace, &wan_flow, "WAN", wan_blocked);
            self.apply_trace_to_links(&lan_trace, &lan_flow, "LAN", lan_blocked);
        }

        // 2. Enforce Actual Network Rules strictly from the Saved / Committed Graph State!
        let ebpf_state = self.enforce_committed_rules(snap, monitor);

        // 3. Update every non-group node strictly from its accumulated connected flow!
        self.update_node_telemetry(
            snap,
            monitor,
            &node_accum,
            max_sys_bytes,
            blackhole_all,
            ebpf_state,
        );
    }

    /// Enforces blocking, socket termination, proxy relay config, and eBPF cgroup hooks
    /// strictly from the last saved (`committed_*`) graph state.
    fn enforce_committed_rules(
        &mut self,
        snap: &NetworkSnapshot,
        monitor: &NetworkMonitor,
    ) -> (bool, String) {
        let blackhole_all = self
            .committed_nodes
            .iter()
            .find(|n| n.kind == NodeKind::InternetGateway)
            .and_then(|n| n.checkbox("Blackhole Drop All"))
            .unwrap_or(false);

        let mut ebpf_proxied_pids: Vec<u32> = Vec::new();
        let mut ebpf_proxied_names: Vec<String> = Vec::new();
        let mut active_proxy_node_idx: Option<usize> = None;

        for i in 0..self.committed_nodes.len() {
            if self.committed_nodes[i].kind != NodeKind::AppGroup {
                continue;
            }
            let gid = self.committed_nodes[i].bound_group_id.unwrap_or(0);
            let member_apps = self.committed_groups.apps_in_group(gid, &snap.apps);

            let wan_trace = trace_exit_path_on(
                &self.committed_nodes,
                &self.committed_links,
                i,
                0,
                &member_apps,
                blackhole_all,
                true,
            );
            let lan_trace = trace_exit_path_on(
                &self.committed_nodes,
                &self.committed_links,
                i,
                1,
                &member_apps,
                blackhole_all,
                true,
            );

            let wan_blocked = !wan_trace.reaches_gateway || wan_trace.blocked;
            let lan_blocked = !lan_trace.reaches_gateway || lan_trace.blocked;

            if wan_trace.proxied && !wan_blocked && wan_trace.proxy_node_idx.is_some() {
                active_proxy_node_idx = wan_trace.proxy_node_idx;
                for (assigned_app, &assigned_gid) in &self.committed_groups.app_to_group {
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
        }

        if let Some(p_idx) = active_proxy_node_idx {
            let p_node = &self.committed_nodes[p_idx];
            let (type_idx, _) = p_node.combo_selected("Type:").unwrap_or((1, ""));
            let srv = p_node
                .text_input("Server:")
                .unwrap_or("127.0.0.1:1080")
                .trim()
                .to_string();
            let usr = p_node.text_input("User:").unwrap_or("").trim().to_string();
            let pwd = p_node.text_input("Pass:").unwrap_or("").trim().to_string();
            let kind = if type_idx == 1 {
                UpstreamProxyKind::HttpConnect
            } else {
                UpstreamProxyKind::Socks5
            };
            monitor.proxy_relay.update_config(UpstreamProxyConfig {
                enabled: true,
                kind,
                server: srv,
                username: usr,
                password: pwd,
            });
        } else {
            monitor
                .proxy_relay
                .update_config(UpstreamProxyConfig::default());
        }

        let state = sync_ebpf_for_apps(&ebpf_proxied_names, &ebpf_proxied_pids);
        self.last_enforced_ebpf_state = state.clone();
        state
    }

    fn apply_trace_to_links(
        &mut self,
        trace: &ExitTraceResult,
        flow: &ScopeFlowData,
        scope_prefix: &str,
        is_blocked: bool,
    ) {
        let spd = flow.total_spd();
        let bytes = flow.total_bytes();
        let calc_intensity = if is_blocked {
            -1.0
        } else if spd >= 1.0 {
            ((spd as f32) / (1024.0 * 256.0)).sqrt().clamp(0.20, 1.0)
        } else {
            0.0
        };

        let primary_badge = if is_blocked {
            format!("{} BLOCKED", scope_prefix)
        } else if let Some(tag) = &trace.route_tag {
            if spd >= 1.0 {
                format!("{}: {} · {}", scope_prefix, tag, format_speed(spd))
            } else {
                format!("{}: {} ({} conns)", scope_prefix, tag, flow.total_socks)
            }
        } else if spd >= 1.0 {
            format!(
                "{}: {} | {}",
                scope_prefix,
                format_speed(spd),
                format_bytes(bytes)
            )
        } else {
            format!("{}: Idle ({} conns)", scope_prefix, flow.total_socks)
        };

        let split_badge = if is_blocked {
            format!("{} BLOCKED", scope_prefix)
        } else {
            format!(
                "{}: ▼ {}  ▲ {}",
                scope_prefix,
                format_speed(flow.down_spd),
                format_speed(flow.up_spd)
            )
        };
        let pkt_badge = if is_blocked {
            format!("{} BLOCKED", scope_prefix)
        } else {
            format!(
                "{}: {:.0} pkts/s | {}",
                scope_prefix,
                flow.pkt_rate,
                format_speed(spd)
            )
        };
        let badge = format!(
            "{}||{}||{}||{:.2}",
            primary_badge, split_badge, pkt_badge, flow.pkt_rate
        );

        for (hop, &l_idx) in trace.visited_links.iter().enumerate() {
            if calc_intensity < 0.0 {
                self.links[l_idx].flow_intensity = -1.0;
                self.links[l_idx].label = format!("{} BLOCKED", scope_prefix);
            } else {
                let prev = self.links[l_idx].flow_intensity.max(0.0);
                let next_val = if calc_intensity == 0.0 && prev < 0.04 {
                    0.0
                } else {
                    prev * 0.78 + calc_intensity * 0.22
                };
                self.links[l_idx].flow_intensity = next_val;
                if hop == 0 || self.links[l_idx].label.is_empty() {
                    self.links[l_idx].label = badge.clone();
                }
            }
        }
    }
}

fn trace_exit_path_on(
    nodes: &[Node],
    links: &[Link],
    start_node_idx: usize,
    exit_slot: usize,
    member_apps: &[&AppNetworkInfo],
    blackhole_all: bool,
    enforce_network: bool,
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
            nodes[cur_node_idx].pin_id_nth(false, exit_slot)
        } else {
            nodes[cur_node_idx].pin_id(false)
        };
        let Some(pin) = out_pin else { break };
        let Some(link_idx) = links.iter().position(|l| l.from == pin) else {
            break;
        };

        res.visited_links.push(link_idx);
        let next_in_pin = links[link_idx].to;
        let Some(next_idx) = nodes.iter().position(|n| {
            n.items
                .iter()
                .any(|it| matches!(it, Item::Pin(p) if p.id == next_in_pin))
        }) else {
            break;
        };
        res.visited_nodes.push(next_idx);

        match nodes[next_idx].kind {
            NodeKind::BlockNode => {
                res.blocked = true;
                break;
            }
            NodeKind::FilterNode => {
                let (mode_idx, _) = nodes[next_idx].combo_selected("Mode:").unwrap_or((0, ""));
                let ports = nodes[next_idx].text_input("Ports:").unwrap_or("");
                let host = nodes[next_idx].text_input("Host:").unwrap_or("");
                if mode_idx == 2 {
                    res.blocked = true;
                } else if enforce_network {
                    drop_matching_sockets(member_apps, mode_idx, exit_slot == 0, ports, host);
                }
            }
            NodeKind::VpnNode if exit_slot == 0 => {
                res.proxied = true;
                let iface = nodes[next_idx].text_input("Iface:").unwrap_or("wg0").trim();
                res.route_tag = Some(format!(
                    "VPN {}",
                    if iface.is_empty() { "wg0" } else { iface }
                ));
            }
            NodeKind::ProxyNode if exit_slot == 0 => {
                res.proxied = true;
                res.proxy_node_idx = Some(next_idx);
                res.route_tag = Some(String::from("Proxy"));
            }
            NodeKind::RateLimiter => {
                let cap = nodes[next_idx]
                    .slider("Max Speed (KB/s)")
                    .unwrap_or(4096.0);
                res.throttled_kbs = Some(res.throttled_kbs.map_or(cap, |prev| prev.min(cap)));
            }
            NodeKind::InternetGateway => {
                res.reaches_gateway = true;
                if nodes[next_idx]
                    .checkbox("Blackhole Drop All")
                    .unwrap_or(false)
                {
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

fn drop_scope_sockets(apps: &[&AppNetworkInfo], drop_remote_wan: bool) {
    for c in apps.iter().flat_map(|a| &a.connections) {
        if c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip()) == drop_remote_wan {
            terminate_single_socket(&c.remote_addr);
        }
    }
}

fn drop_matching_sockets(
    apps: &[&AppNetworkInfo],
    mode_idx: usize,
    wan_scope: bool,
    ports_filter: &str,
    host_filter: &str,
) {
    let parsed_ports: Vec<u16> = ports_filter
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|s| s.trim().parse().ok())
        .collect();
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
        let host_ok = host_q.is_empty()
            || conn.remote_addr.ip().to_string().contains(&host_q)
            || conn
                .domain
                .as_ref()
                .is_some_and(|d| d.to_lowercase().contains(&host_q));
        if (mode_idx == 0 && !(port_ok && host_ok)) || (mode_idx == 1 && port_ok && host_ok) {
            terminate_single_socket(&conn.remote_addr);
        }
    }
}
