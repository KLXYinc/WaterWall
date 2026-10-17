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
        String::from("Reset Flow Graph to default (Press Ctrl+Z to undo)")
    }

    /// Saves the complete Flow Graph (nodes, positions, settings, links, and app groups) to disk.
    pub fn save_to_disk(&self, groups: &AppGroupManager) -> String {
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
        }

        for l in &self.links {
            out.push_str(&format!("LINK|{}|{}|{}\n", l.id, l.from, l.to));
        }

        let path = graph_save_path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::write(&path, &out) {
            Ok(_) => format!("Saved Flow Graph to {}", path.display()),
            Err(e) => format!("Failed to save Flow Graph: {}", e),
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
                "LINK" if parts.len() >= 4 => {
                    if let (Ok(id), Ok(from), Ok(to)) =
                        (parts[1].parse(), parts[2].parse(), parts[3].parse())
                    {
                        links.push(Link {
                            id,
                            from,
                            to,
                            flow_intensity: 0.35,
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
