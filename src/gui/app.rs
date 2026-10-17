use imgui::node_graph as ng;
use imgui::{Condition, StyleColor, StyleVar, Ui, WindowFlags};

use super::alerts_view;
use super::canvas;
use super::graph::Graph;
use super::icons::IconManager;
use super::monitor_view::{self, MonitorViewState};
use super::theme;
use super::toolbar;
use super::traffic_view::{self, TrafficViewState};
use super::usage_view;
use super::widgets::SharedFilterState;
use crate::net::NetworkMonitor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewMode {
    Usage,          // [1] Network Usage: Doughnut, Countries, Apps, Hosts/IPs, Protocols
    TrafficMonitor, // [2] Traffic Monitor: GlassWire Multi-App Colored Bandwidth Graph
    Firewall,       // [3] App Connections: Per-App Group Assignment & Live Socket Inspector
    FlowGraph,      // [4] Flow Graph: App Group Nodes, Configurable Filter/Block/VPN/Proxy Nodes & Physics Ropes
    DnsAndAlerts,   // [5] DNS & Alerts: Live DNS Resolution Tracker & GlassWire Security Alerts
}

pub struct WaterWallApp {
    pub should_exit: bool,
    pub view_mode: ViewMode,
    pub graph: Graph,
    pub monitor: NetworkMonitor,
    pub filter: SharedFilterState,
    pub monitor_state: MonitorViewState,
    pub traffic_state: TrafficViewState,
    pub icon_manager: IconManager,
    pub status: String,
    pub context_click_pos: Option<[f32; 2]>,
    pub editing_group_id: Option<usize>,
}

impl Default for WaterWallApp {
    fn default() -> Self {
        Self::new()
    }
}

impl WaterWallApp {
    pub fn new() -> Self {
        ng::set_pan(theme::INITIAL_PAN);
        let mut graph = Graph::starter();
        let mut filter = SharedFilterState::default();
        let status = graph
            .load_from_disk(&mut filter.groups)
            .unwrap_or_else(|| String::from("Ready — Drag node onto rope to insert | Ctrl+Z: Undo | Ctrl+S: Save"));
        graph.commit_network_state(&filter.groups);
        Self {
            should_exit: false,
            view_mode: ViewMode::Usage,
            graph,
            monitor: NetworkMonitor::new(),
            filter,
            monitor_state: MonitorViewState::default(),
            traffic_state: TrafficViewState::default(),
            icon_manager: IconManager::new(),
            status,
            context_click_pos: None,
            editing_group_id: None,
        }
    }

    pub fn build(&mut self, ui: &Ui, gl: &glow::Context) {
        self.root_window(ui, gl);
    }

    pub fn shutdown(&mut self) {
        self.monitor.stop();
    }

    fn root_window(&mut self, ui: &Ui, gl: &glow::Context) {
        let display = ui.io().display_size;
        let _border = ui.push_style_var(StyleVar::WindowBorderSize(0.0));
        let _bg = ui.push_style_color(StyleColor::WindowBg, theme::WINDOW_BG);
        ui.window("WaterWall")
            .flags(ROOT_WINDOW_FLAGS)
            .position([0.0, 0.0], Condition::Always)
            .size(display, Condition::Always)
            .build(|| {
                let snap = self.monitor.snapshot();
                self.graph
                    .sync_with_monitor(&snap, &self.filter.groups, &self.monitor);

                toolbar::render_toolbar(self, &snap, ui);

                match self.view_mode {
                    ViewMode::Usage => {
                        usage_view::render_usage_view(
                            &mut self.filter,
                            &snap,
                            &self.monitor,
                            &mut self.icon_manager,
                            gl,
                            ui,
                        );
                    }
                    ViewMode::TrafficMonitor => {
                        traffic_view::render_traffic_monitor_view(
                            &mut self.traffic_state,
                            &mut self.filter,
                            &snap,
                            &self.monitor,
                            &mut self.icon_manager,
                            gl,
                            ui,
                        );
                    }
                    ViewMode::Firewall => {
                        monitor_view::render_firewall_split_view(
                            &mut self.monitor_state,
                            &mut self.filter,
                            &snap,
                            &self.monitor,
                            &mut self.icon_manager,
                            gl,
                            ui,
                        );
                    }
                    ViewMode::FlowGraph => {
                        canvas::render_canvas(self, &snap, gl, ui);
                    }
                    ViewMode::DnsAndAlerts => {
                        alerts_view::render_dns_and_alerts_view(
                            &mut self.filter,
                            &snap,
                            &self.monitor,
                            ui,
                        );
                    }
                }

                if self.filter.request_flow_graph {
                    self.filter.request_flow_graph = false;
                    self.view_mode = ViewMode::FlowGraph;
                }
            });
    }
}

const ROOT_WINDOW_FLAGS: WindowFlags = WindowFlags::from_bits_truncate(
    WindowFlags::NO_TITLE_BAR.bits()
        | WindowFlags::NO_RESIZE.bits()
        | WindowFlags::NO_MOVE.bits()
        | WindowFlags::NO_COLLAPSE.bits()
        | WindowFlags::NO_SCROLLBAR.bits()
        | WindowFlags::NO_SCROLL_WITH_MOUSE.bits()
        | WindowFlags::NO_SAVED_SETTINGS.bits()
        | WindowFlags::NO_NAV_FOCUS.bits()
        | WindowFlags::NO_BRING_TO_FRONT_ON_FOCUS.bits(),
);
