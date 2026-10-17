pub mod flow_calc;
pub mod history;
pub mod sync;
pub mod telemetry;

use imgui::node_graph as ng;
use imgui::Ui;

use self::history::GraphSnapshot;
use crate::gui::groups::AppGroupManager;
use crate::gui::nodes::{rope_kind_name, Item, Link, Node, NodeKind};

pub struct Graph {
    pub(crate) nodes: Vec<Node>,
    pub(crate) links: Vec<Link>,
    pub(crate) next_node_id: i32,
    pub(crate) next_link_id: i32,
    pub(crate) undo_stack: Vec<GraphSnapshot>,
    pub(crate) redo_stack: Vec<GraphSnapshot>,
    pub(crate) drag_start_snapshot: Option<GraphSnapshot>,
    pub(crate) structural_change_during_drag: bool,
    pub(crate) committed_nodes: Vec<Node>,
    pub(crate) committed_links: Vec<Link>,
    pub(crate) committed_groups: AppGroupManager,
    pub(crate) committed_sig: String,
    pub(crate) last_enforced_ebpf_state: (bool, String),
}

impl Graph {
    pub fn starter() -> Self {
        let mut graph = Self::empty();
        let filter = graph.push_node(NodeKind::FilterNode, [360.0, 55.0]);
        let monitor = graph.push_node(NodeKind::TrafficMonitor, [670.0, 60.0]);
        let sink = graph.push_node(NodeKind::InternetGateway, [970.0, 80.0]);

        let flt_in = graph.nodes[filter].pin_id(true).unwrap();
        let flt_out = graph.nodes[filter].pin_id(false).unwrap();
        let mon_in = graph.nodes[monitor].pin_id(true).unwrap();
        let mon_out = graph.nodes[monitor].pin_id(false).unwrap();
        let snk_wan_in = graph.nodes[sink].pin_id_nth(true, 0).unwrap();
        let snk_lan_in = graph.nodes[sink].pin_id_nth(true, 1).unwrap();

        let grp = graph.push_group_node(
            0,
            "All Apps (Default)",
            [0.15, 0.88, 0.65, 1.0],
            [35.0, 65.0],
        );
        let grp_wan_out = graph.nodes[grp].pin_id_nth(false, 0).unwrap();
        let grp_lan_out = graph.nodes[grp].pin_id_nth(false, 1).unwrap();

        // Remote WAN goes through Filter -> Live Traffic Probe -> Gateway [In: Remote WAN]
        graph.push_link_multi(grp_wan_out, flt_in);
        graph.push_link_multi(flt_out, mon_in);
        graph.push_link_multi(mon_out, snk_wan_in);

        // Local LAN goes directly from AppGroup [Out: Local LAN] -> Gateway [In: Local LAN]
        graph.push_link_multi(grp_lan_out, snk_lan_in);
        let default_groups = AppGroupManager::new();
        graph.commit_network_state(&default_groups);
        graph
    }

    pub fn empty() -> Self {
        Self {
            nodes: Vec::new(),
            links: Vec::new(),
            next_node_id: 1,
            next_link_id: 1,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            drag_start_snapshot: None,
            structural_change_during_drag: false,
            committed_nodes: Vec::new(),
            committed_links: Vec::new(),
            committed_groups: AppGroupManager::new(),
            committed_sig: String::new(),
            last_enforced_ebpf_state: (false, String::from("eBPF Standby")),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn find_node_by_pin(&self, pin_id: i32) -> Option<usize> {
        self.nodes.iter().position(|n| {
            n.items
                .iter()
                .any(|it| matches!(it, Item::Pin(p) if p.id == pin_id))
        })
    }

    pub fn push_group_node(
        &mut self,
        group_id: usize,
        name: &str,
        color: [f32; 4],
        pos: [f32; 2],
    ) -> usize {
        if let Some(idx) = self
            .nodes
            .iter()
            .position(|n| n.kind == NodeKind::AppGroup && n.bound_group_id == Some(group_id))
        {
            self.nodes[idx].title = name.to_string();
            self.nodes[idx].accent = color;
            return idx;
        }

        let id = self.next_node_id;
        self.next_node_id += 1;
        let mut node = Node::new(NodeKind::AppGroup, id, pos);
        node.title = name.to_string();
        node.bound_group_id = Some(group_id);
        node.accent = color;
        let wan_out = node.pin_id_nth(false, 0);
        let lan_out = node.pin_id_nth(false, 1);
        self.nodes.push(node);
        let new_idx = self.nodes.len() - 1;

        if let Some(src_wan) = wan_out {
            if let Some(target_wan_in) = self
                .nodes
                .iter()
                .find(|n| n.kind == NodeKind::InternetGateway)
                .and_then(|n| n.pin_id_nth(true, 0))
            {
                self.push_link_multi(src_wan, target_wan_in);
            }
        }
        if let Some(src_lan) = lan_out {
            if let Some(target_lan_in) = self
                .nodes
                .iter()
                .find(|n| n.kind == NodeKind::InternetGateway)
                .and_then(|n| n.pin_id_nth(true, 1))
            {
                self.push_link_multi(src_lan, target_lan_in);
            }
        }
        new_idx
    }

    /// Checks whether a pin originates from a `Local LAN` exit (either directly or through middle nodes).
    pub fn is_lan_origin_pin(&self, mut pin_id: i32) -> bool {
        for _ in 0..6 {
            let Some(node_idx) = self.find_node_by_pin(pin_id) else {
                return false;
            };
            let node = &self.nodes[node_idx];
            if node.kind == NodeKind::AppGroup {
                return node.pin_id_nth(false, 1) == Some(pin_id);
            }
            let Some(in_pin) = node.pin_id(true) else {
                return false;
            };
            let Some(prev_link) = self.links.iter().find(|l| l.to == in_pin) else {
                return false;
            };
            pin_id = prev_link.from;
        }
        false
    }

    /// Validates whether connecting `from_pin -> to_pin` makes networking sense.
    pub fn validate_connection(&self, from_pin: i32, to_pin: i32) -> Result<(), &'static str> {
        let Some(dst_idx) = self.find_node_by_pin(to_pin) else {
            return Err("Target pin is not a valid input");
        };
        let dst_node = &self.nodes[dst_idx];
        let is_input_pin = dst_node
            .items
            .iter()
            .any(|it| matches!(it, Item::Pin(p) if p.id == to_pin && p.is_input));
        if !is_input_pin {
            return Err("Target pin is not a valid input");
        }

        let is_lan = self.is_lan_origin_pin(from_pin);

        // Local LAN traffic never routes through VPN or Proxy tunnels
        if is_lan && dst_node.kind.is_wan_only() {
            return Err("Rejected: Local LAN traffic does not use VPN or Proxy (Remote WAN only)");
        }

        // Gateway pin matching: In: Remote WAN (slot 0) vs In: Local LAN (slot 1)
        if dst_node.kind == NodeKind::InternetGateway {
            let gw_wan_in = dst_node.pin_id_nth(true, 0);
            let gw_lan_in = dst_node.pin_id_nth(true, 1);
            if is_lan && Some(to_pin) == gw_wan_in {
                return Err("Rejected: Connect Local LAN stream to 'In: Local LAN' on Gateway");
            }
            if !is_lan && Some(to_pin) == gw_lan_in {
                return Err("Rejected: Connect Remote WAN stream to 'In: Remote WAN' on Gateway");
            }
        }

        Ok(())
    }

    pub fn auto_layout(&mut self) -> String {
        self.push_undo();
        let (mut c0, mut c1, mut c2, mut c3) = (50.0f32, 40.0f32, 65.0f32, 85.0f32);
        for node in &mut self.nodes {
            match node.kind {
                NodeKind::AppGroup => {
                    node.pos = [35.0, c0];
                    c0 += 215.0;
                }
                NodeKind::FilterNode
                | NodeKind::BlockNode
                | NodeKind::VpnNode
                | NodeKind::ProxyNode
                | NodeKind::RateLimiter => {
                    node.pos = [360.0, c1];
                    c1 += 190.0;
                }
                NodeKind::TrafficMonitor => {
                    node.pos = [670.0, c2];
                    c2 += 190.0;
                }
                NodeKind::InternetGateway => {
                    node.pos = [970.0, c3];
                    c3 += 185.0;
                }
            }
        }
        String::from("Arranged Group & Policy nodes (Ctrl+Z to undo)")
    }

    pub fn remove_node(&mut self, id: i32) -> String {
        let i = match self.nodes.iter().position(|n| n.id == id) {
            Some(i) => i,
            None => return format!("Unknown node {id}"),
        };
        if !self.nodes[i].kind.is_deletable() || self.nodes[i].bound_group_id == Some(0) {
            return format!(
                "'{}' is a core endpoint and cannot be deleted",
                self.nodes[i].title
            );
        }
        self.push_undo();
        self.structural_change_during_drag = true;
        let node = self.nodes.remove(i);
        let pins: Vec<i32> = node
            .items
            .iter()
            .filter_map(|it| match it {
                Item::Pin(p) => Some(p.id),
                _ => None,
            })
            .collect();
        self.links
            .retain(|l| !pins.contains(&l.from) && !pins.contains(&l.to));
        format!("Deleted '{}' (Ctrl+Z to undo)", node.title)
    }

    pub fn declare(&mut self, ui: &Ui) {
        for node in &mut self.nodes {
            node.declare(ui);
        }
        for link in &mut self.links {
            ng::link_flow(
                ui,
                link.id,
                link.from,
                link.to,
                link.flow_intensity,
                &link.label,
            );
            if !link.kind_synced {
                if link.rope_kind != 0 {
                    ng::set_link_kind(link.id, link.rope_kind);
                }
                link.kind_synced = true;
            }
        }
    }

    pub fn track_drag_undo(&mut self, lmb_clicked: bool, lmb_released: bool) {
        if lmb_clicked {
            self.drag_start_snapshot = Some(self.capture_snapshot());
            self.structural_change_during_drag = false;
        }
        if lmb_released {
            if let Some(start_snap) = self.drag_start_snapshot.take() {
                if !self.structural_change_during_drag
                    && start_snap.nodes.len() == self.nodes.len()
                {
                    let moved = start_snap.nodes.iter().zip(self.nodes.iter()).any(|(a, b)| {
                        (a.pos[0] - b.pos[0]).abs() > 2.5 || (a.pos[1] - b.pos[1]).abs() > 2.5
                    });
                    if moved {
                        self.push_undo_snapshot(start_snap);
                    }
                }
            }
            self.structural_change_during_drag = false;
        }
    }

    pub fn take_clicked_group_apps(&mut self) -> Option<usize> {
        for node in &mut self.nodes {
            if node.kind == NodeKind::AppGroup && node.take_group_apps_clicked() {
                if let Some(gid) = node.bound_group_id {
                    return Some(gid);
                }
            }
        }
        None
    }

    pub fn apply(&mut self, event: ng::Event) -> String {
        match event {
            ng::Event::Connected { from, to } => match self.validate_connection(from, to) {
                Ok(()) => {
                    self.push_undo();
                    self.structural_change_during_drag = true;
                    self.push_link_multi(from, to);
                    format!("Connected rope {from} -> {to} (Ctrl+Z to undo)")
                }
                Err(reason) => String::from(reason),
            },
            ng::Event::Removed { link } => {
                if self.links.iter().any(|l| l.id == link) {
                    self.push_undo();
                    self.structural_change_during_drag = true;
                }
                self.links.retain(|l| l.id != link);
                format!("Disconnected rope {link} (Ctrl+Z to undo)")
            }
            ng::Event::Focused { node } => match self.nodes.iter().position(|n| n.id == node) {
                Some(i) => {
                    let title = self.nodes[i].title.clone();
                    let n = self.nodes.remove(i);
                    self.nodes.push(n);
                    format!("Focused '{title}'")
                }
                None => String::new(),
            },
            ng::Event::RmbNode { node } => self.remove_node(node),
            ng::Event::InsertNode { node, link } => self.insert_node_on_link(node, link),
            ng::Event::RopeKindChanged { link, kind } => {
                if let Some(l) = self.links.iter_mut().find(|l| l.id == link) {
                    l.rope_kind = kind;
                    l.kind_synced = true;
                }
                format!("Rope style: {} (Ctrl+S to save)", rope_kind_name(kind))
            }
            ng::Event::CountryClicked { .. } | ng::Event::RmbCanvas { .. } => String::new(),
        }
    }

    pub fn insert_node_on_link(&mut self, node_id: i32, link_id: i32) -> String {
        let (from_pin, to_pin) = match self.links.iter().find(|l| l.id == link_id) {
            Some(l) => (l.from, l.to),
            None => return String::new(),
        };

        let is_lan = self.is_lan_origin_pin(from_pin);

        let (in_pin, out_pin, title, kind) = match self.nodes.iter().find(|n| n.id == node_id) {
            Some(n) => match (n.pin_id(true), n.pin_id(false)) {
                (Some(i), Some(o)) => (i, o, n.title.clone(), n.kind),
                _ => return String::from("Block Node is a terminal sink and cannot splice mid-rope"),
            },
            None => return String::new(),
        };

        if is_lan && kind.is_wan_only() {
            return format!("Rejected: '{}' only supports Remote WAN ropes, not Local LAN", title);
        }

        if let Some(drag_snap) = self.drag_start_snapshot.take() {
            self.push_undo_snapshot(drag_snap);
        } else {
            self.push_undo();
        }
        self.structural_change_during_drag = true;

        self.links.retain(|l| l.id != link_id);
        self.push_link_multi(from_pin, in_pin);
        self.push_link_multi(out_pin, to_pin);
        format!("Inserted '{title}' onto rope (Ctrl+Z to undo)")
    }

    pub fn add_node_at(&mut self, kind: NodeKind, pos: [f32; 2]) -> String {
        self.push_undo();
        self.push_node(kind, pos);
        format!("Added '{}' node (Ctrl+Z to undo)", kind.title())
    }

    pub fn push_node(&mut self, kind: NodeKind, pos: [f32; 2]) -> usize {
        let id = self.next_node_id;
        self.next_node_id += 1;
        self.nodes.push(Node::new(kind, id, pos));
        self.nodes.len() - 1
    }

    pub fn push_link_multi(&mut self, from: i32, to: i32) {
        self.links
            .retain(|l| l.from != from && !(l.from == from && l.to == to));
        let id = self.next_link_id;
        self.next_link_id += 1;
        self.links.push(Link {
            id,
            from,
            to,
            flow_intensity: 0.0,
            rope_kind: 0,
            kind_synced: true,
            label: String::new(),
        });
    }
}
