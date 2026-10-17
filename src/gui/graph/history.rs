use std::fs;

use super::Graph;
use crate::gui::groups::{AppGroup, AppGroupManager, GLASSWIRE_PALETTE};
use crate::gui::nodes::{Item, Link, Node, NodeKind};
use crate::utils::graph_save_path;

const MAX_UNDO_HISTORY: usize = 64;

#[derive(Clone)]
pub struct GraphSnapshot {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    pub next_node_id: i32,
    pub next_link_id: i32,
}

impl Graph {
    pub fn capture_snapshot(&self) -> GraphSnapshot {
        GraphSnapshot {
            nodes: self.nodes.clone(),
            links: self.links.clone(),
            next_node_id: self.next_node_id,
            next_link_id: self.next_link_id,
        }
    }

    pub fn restore_snapshot(&mut self, snap: GraphSnapshot) {
        self.nodes = snap.nodes;
        self.links = snap.links;
        for l in &mut self.links {
            l.kind_synced = false;
        }
        self.next_node_id = snap.next_node_id;
        self.next_link_id = snap.next_link_id;
    }

    pub fn push_undo(&mut self) {
        let snap = self.capture_snapshot();
        self.push_undo_snapshot(snap);
    }

    pub fn push_undo_snapshot(&mut self, snap: GraphSnapshot) {
        if self.undo_stack.len() >= MAX_UNDO_HISTORY {
            self.undo_stack.remove(0);
        }
        self.undo_stack.push(snap);
        self.redo_stack.clear();
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    pub fn undo(&mut self) -> String {
        if let Some(prev) = self.undo_stack.pop() {
            let current = self.capture_snapshot();
            self.redo_stack.push(current);
            self.restore_snapshot(prev);
            format!("Undo applied ({} steps remaining)", self.undo_stack.len())
        } else {
            String::from("Nothing to undo")
        }
    }

    pub fn redo(&mut self) -> String {
        if let Some(next) = self.redo_stack.pop() {
            let current = self.capture_snapshot();
            self.undo_stack.push(current);
            self.restore_snapshot(next);
            format!("Redo applied ({} steps remaining)", self.redo_stack.len())
        } else {
            String::from("Nothing to redo")
        }
    }

    /// Resets the graph to the default starter layout while saving the previous state in Undo history.
    pub fn reset_with_undo(&mut self) -> String {
        self.push_undo();
        let fresh = Self::starter();
        self.nodes = fresh.nodes;
        self.links = fresh.links;
        self.next_node_id = fresh.next_node_id;
        self.next_link_id = fresh.next_link_id;
        imgui::node_graph::reset_interaction();
        imgui::node_graph::set_pan(crate::gui::theme::INITIAL_PAN);
        String::from("Reset Flow Graph (Unsaved — Click Save or Ctrl+S to apply network rules)")
    }

    /// Computes a deterministic signature of all policy-relevant graph state (ropes, nodes, settings, and app groups).
    pub fn compute_policy_sig(&self, groups: &AppGroupManager) -> String {
        let mut sig = String::with_capacity(512);
        let mut assigns: Vec<(&String, &usize)> = groups.app_to_group.iter().collect();
        assigns.sort_by_key(|(k, _)| *k);
        for (app, gid) in assigns {
            sig.push_str(&format!("A:{}:{};", app, gid));
        }

        let mut sorted_nodes: Vec<&Node> = self.nodes.iter().collect();
        sorted_nodes.sort_by_key(|n| n.id);
        for n in sorted_nodes {
            sig.push_str(&format!(
                "N:{}:{}:{:?};",
                n.id,
                kind_to_tag(n.kind),
                n.bound_group_id
            ));
            for item in &n.items {
                match item {
                    Item::TextInput { label, value, .. } => {
                        sig.push_str(&format!("T:{}:{};", label, value.trim()));
                    }
                    Item::Combo {
                        label, selected, ..
                    } => {
                        sig.push_str(&format!("C:{}:{};", label, selected));
                    }
                    Item::Checkbox { label, value } => {
                        sig.push_str(&format!("K:{}:{};", label, value));
                    }
                    Item::Slider { label, value, .. } => {
                        sig.push_str(&format!("S:{}:{:.1};", label, value));
                    }
                    _ => {}
                }
            }
            if n.kind == NodeKind::TrafficMonitor {
                sig.push_str(&format!(
                    "P:{}:{}:{}:{};",
                    n.probe_config.variant as usize,
                    n.probe_config.wave_channel as usize,
                    n.probe_config.show_meter,
                    n.probe_config.show_wave
                ));
            }
        }

        let mut sorted_links: Vec<(i32, i32, i32)> = self
            .links
            .iter()
            .map(|l| (l.from, l.to, l.rope_kind))
            .collect();
        sorted_links.sort_unstable();
        for (from, to, rkind) in sorted_links {
            sig.push_str(&format!("L:{}->{}:{};", from, to, rkind));
        }
        sig
    }

    /// Commits the current nodes, ropes, and app groups as the active saved network policy.
    pub fn commit_network_state(&mut self, groups: &AppGroupManager) {
        self.committed_nodes = self.nodes.clone();
        self.committed_links = self.links.clone();
        self.committed_groups = groups.clone();
        self.committed_sig = self.compute_policy_sig(groups);
    }

    /// Returns `true` if there are unsaved rope, node, setting, or app-group changes pending Save.
    pub fn has_unsaved_changes(&self, groups: &AppGroupManager) -> bool {
        self.compute_policy_sig(groups) != self.committed_sig
    }

    /// Saves the complete Flow Graph (nodes, positions, settings, links, and app groups) to disk
    /// and commits the network rules so they take effect immediately.
    pub fn save_to_disk(&mut self, groups: &AppGroupManager) -> String {
        let mut out = String::from("# WaterWall Flow Graph & App Groups v1\n");
        out.push_str(&format!(
            "META|{}|{}\n",
            self.next_node_id, self.next_link_id
        ));

        for g in &groups.groups {
            if g.id != 0 {
                out.push_str(&format!("GROUP|{}|{}\n", g.id, g.name.replace('|', "/")));
            }
        }
        for (app, gid) in &groups.app_to_group {
            out.push_str(&format!("ASSIGN|{}|{}\n", app.replace('|', "/"), gid));
        }

        for n in &self.nodes {
            let kind_str = kind_to_tag(n.kind);
            let bgid = n.bound_group_id.map(|g| g.to_string()).unwrap_or_default();
            out.push_str(&format!(
                "NODE|{}|{}|{:.1}|{:.1}|{}|{}\n",
                n.id,
                kind_str,
                n.pos[0],
                n.pos[1],
                bgid,
                n.title.replace('|', "/")
            ));
            for item in &n.items {
                match item {
                    Item::TextInput { label, value, .. } => {
                        out.push_str(&format!(
                            "ITEM_TXT|{}|{}|{}\n",
                            n.id,
                            label,
                            value.replace('|', "/")
                        ));
                    }
                    Item::Combo {
                        label, selected, ..
                    } => {
                        out.push_str(&format!("ITEM_CMB|{}|{}|{}\n", n.id, label, selected));
                    }
                    Item::Checkbox { label, value } => {
                        out.push_str(&format!("ITEM_CHK|{}|{}|{}\n", n.id, label, value));
                    }
                    Item::Slider { label, value, .. } => {
                        out.push_str(&format!("ITEM_SLD|{}|{}|{:.2}\n", n.id, label, value));
                    }
                    _ => {}
                }
            }
            if n.kind == NodeKind::TrafficMonitor {
                out.push_str(&format!(
                    "PROBE_CFG|{}|{}|{}|{}|{}\n",
                    n.id,
                    n.probe_config.variant as usize,
                    n.probe_config.wave_channel as usize,
                    n.probe_config.show_meter,
                    n.probe_config.show_wave
                ));
            }
        }

        for l in &self.links {
            out.push_str(&format!("LINK|{}|{}|{}|{}\n", l.id, l.from, l.to, l.rope_kind));
        }

        let path = graph_save_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        self.commit_network_state(groups);
        match fs::write(&path, &out) {
            Ok(_) => format!("Saved & applied network rules ({})", path.display()),
            Err(e) => format!("Applied network rules (disk save error: {})", e),
        }
    }

    /// Loads the Flow Graph and App Groups from disk if a saved configuration exists.
    pub fn load_from_disk(&mut self, groups: &mut AppGroupManager) -> Option<String> {
        let path = graph_save_path();
        let content = fs::read_to_string(&path).ok()?;

        let mut nodes: Vec<Node> = Vec::new();
        let mut links: Vec<Link> = Vec::new();
        let mut next_node_id = 1i32;
        let mut next_link_id = 1i32;

        groups.groups.truncate(5);
        groups.app_to_group.clear();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('|').collect();
            match parts.first().copied().unwrap_or("") {
                "META" if parts.len() >= 3 => {
                    next_node_id = parts[1].parse().unwrap_or(1);
                    next_link_id = parts[2].parse().unwrap_or(1);
                }
                "GROUP" if parts.len() >= 3 => {
                    if let Ok(gid) = parts[1].parse::<usize>() {
                        if !groups.groups.iter().any(|g| g.id == gid) {
                            let col = GLASSWIRE_PALETTE[gid % GLASSWIRE_PALETTE.len()];
                            groups.groups.push(AppGroup {
                                id: gid,
                                name: parts[2].to_string(),
                                color: col,
                            });
                        }
                    }
                }
                "ASSIGN" if parts.len() >= 3 => {
                    if let Ok(gid) = parts[2].parse::<usize>() {
                        groups.assign_app(parts[1], gid);
                    }
                }
                "NODE" if parts.len() >= 7 => {
                    let id = parts[1].parse().unwrap_or(1);
                    let Some(kind) = tag_to_kind(parts[2]) else {
                        continue;
                    };
                    let x = parts[3].parse().unwrap_or(40.0);
                    let y = parts[4].parse().unwrap_or(60.0);
                    let bgid = parts[5].parse::<usize>().ok();
                    let mut n = Node::new(kind, id, [x, y]);
                    n.bound_group_id = bgid;
                    n.title = parts[6].to_string();
                    if let Some(gid) = bgid {
                        if let Some(grp) = groups.get_group(gid) {
                            n.accent = grp.color;
                        }
                    }
                    nodes.push(n);
                }
                "ITEM_TXT" if parts.len() >= 4 => {
                    if let Ok(nid) = parts[1].parse::<i32>() {
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == nid) {
                            for it in &mut n.items {
                                if let Item::TextInput { label, value, .. } = it {
                                    if *label == parts[2] {
                                        *value = parts[3].to_string();
                                    }
                                }
                            }
                        }
                    }
                }
                "ITEM_CMB" if parts.len() >= 4 => {
                    if let (Ok(nid), Ok(sel)) = (parts[1].parse::<i32>(), parts[3].parse::<usize>())
                    {
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == nid) {
                            for it in &mut n.items {
                                if let Item::Combo {
                                    label,
                                    selected,
                                    options,
                                } = it
                                {
                                    if *label == parts[2] && sel < options.len() {
                                        *selected = sel;
                                    }
                                }
                            }
                        }
                    }
                }
                "ITEM_CHK" if parts.len() >= 4 => {
                    if let (Ok(nid), Ok(val)) = (parts[1].parse::<i32>(), parts[3].parse::<bool>())
                    {
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == nid) {
                            for it in &mut n.items {
                                if let Item::Checkbox { label, value } = it {
                                    if *label == parts[2] {
                                        *value = val;
                                    }
                                }
                            }
                        }
                    }
                }
                "ITEM_SLD" if parts.len() >= 4 => {
                    if let (Ok(nid), Ok(val)) = (parts[1].parse::<i32>(), parts[3].parse::<f32>())
                    {
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == nid) {
                            for it in &mut n.items {
                                if let Item::Slider { label, value, min, max } = it {
                                    if *label == parts[2] {
                                        *value = val.clamp(*min, *max);
                                    }
                                }
                            }
                        }
                    }
                }
                "PROBE_CFG" if parts.len() >= 6 => {
                    if let Ok(nid) = parts[1].parse::<i32>() {
                        if let Some(n) = nodes.iter_mut().find(|n| n.id == nid) {
                            let var_idx = parts[2].parse::<usize>().unwrap_or(0);
                            let ch_idx = parts[3].parse::<usize>().unwrap_or(0);
                            n.probe_config.variant =
                                crate::gui::nodes::ProbeVariant::from_index(var_idx);
                            n.probe_config.wave_channel =
                                crate::gui::nodes::ProbeWaveChannel::from_index(ch_idx);
                            n.probe_config.show_meter = parts[4].parse().unwrap_or(true);
                            n.probe_config.show_wave = parts[5].parse().unwrap_or(true);
                        }
                    }
                }
                "LINK" if parts.len() >= 4 => {
                    if let (Ok(id), Ok(from), Ok(to)) =
                        (parts[1].parse(), parts[2].parse(), parts[3].parse())
                    {
                        let rope_kind = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                        links.push(Link {
                            id,
                            from,
                            to,
                            flow_intensity: 0.0,
                            rope_kind,
                            kind_synced: false,
                            label: String::new(),
                        });
                    }
                }
                _ => {}
            }
        }

        if nodes.is_empty() {
            return None;
        }

        self.nodes = nodes;
        self.links = links;
        self.next_node_id = next_node_id.max(self.nodes.iter().map(|n| n.id + 1).max().unwrap_or(1));
        self.next_link_id = next_link_id.max(self.links.iter().map(|l| l.id + 1).max().unwrap_or(1));
        self.commit_network_state(groups);
        Some(format!("Loaded saved Flow Graph from {}", path.display()))
    }
}

fn kind_to_tag(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::AppGroup => "AppGroup",
        NodeKind::FilterNode => "FilterNode",
        NodeKind::BlockNode => "BlockNode",
        NodeKind::VpnNode => "VpnNode",
        NodeKind::ProxyNode => "ProxyNode",
        NodeKind::RateLimiter => "RateLimiter",
        NodeKind::TrafficMonitor => "TrafficMonitor",
        NodeKind::InternetGateway => "InternetGateway",
    }
}

fn tag_to_kind(tag: &str) -> Option<NodeKind> {
    match tag {
        "AppGroup" => Some(NodeKind::AppGroup),
        "FilterNode" => Some(NodeKind::FilterNode),
        "BlockNode" => Some(NodeKind::BlockNode),
        "VpnNode" => Some(NodeKind::VpnNode),
        "ProxyNode" => Some(NodeKind::ProxyNode),
        "RateLimiter" => Some(NodeKind::RateLimiter),
        "TrafficMonitor" => Some(NodeKind::TrafficMonitor),
        "InternetGateway" => Some(NodeKind::InternetGateway),
        _ => None,
    }
}
