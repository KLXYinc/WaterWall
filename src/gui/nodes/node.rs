use imgui::node_graph as ng;
use imgui::Ui;

use super::item::{Item, WAVE_SAMPLES};
use super::probe::ProbeConfig;
use super::NodeKind;
use crate::utils::{parse_proxy_url, read_system_clipboard};

#[derive(Clone)]
pub struct Node {
    pub id: i32,
    pub kind: NodeKind,
    pub title: String,
    pub bound_group_id: Option<usize>,
    pub pos: [f32; 2],
    pub width: f32,
    pub accent: [f32; 4],
    pub items: Vec<Item>,
    pub probe_config: ProbeConfig,
}

impl Node {
    pub fn new(kind: NodeKind, id: i32, pos: [f32; 2]) -> Self {
        let probe_config = ProbeConfig::default();
        let title = if kind == NodeKind::TrafficMonitor {
            probe_config.variant.header_title().to_string()
        } else {
            kind.title().to_string()
        };
        Self {
            id,
            kind,
            title,
            bound_group_id: None,
            pos,
            width: kind.width(),
            accent: kind.accent(),
            items: kind.default_items(id),
            probe_config,
        }
    }

    fn is_item_visible(&self, item: &Item) -> bool {
        if self.kind != NodeKind::TrafficMonitor {
            return true;
        }
        match item {
            Item::DataMeter { .. } => self.probe_config.show_meter,
            Item::WaveGraph { .. } => self.probe_config.show_wave,
            _ => true,
        }
    }

    pub fn content_height(&self) -> f32 {
        self.items
            .iter()
            .filter(|it| self.is_item_visible(it))
            .map(Item::height)
            .sum()
    }

    pub fn pin_id(&self, is_input: bool) -> Option<i32> {
        self.items.iter().find_map(|item| match item {
            Item::Pin(p) if p.is_input == is_input => Some(p.id),
            _ => None,
        })
    }

    pub fn pin_id_nth(&self, is_input: bool, nth: usize) -> Option<i32> {
        self.items
            .iter()
            .filter_map(|item| match item {
                Item::Pin(p) if p.is_input == is_input => Some(p.id),
                _ => None,
            })
            .nth(nth)
    }

    pub fn set_readout(&mut self, label: &str, new_val: String, new_col: Option<[f32; 4]>) {
        for item in &mut self.items {
            if let Item::Readout {
                label: l,
                value,
                color,
            } = item
            {
                if *l == label {
                    *value = new_val;
                    if let Some(c) = new_col {
                        *color = c;
                    }
                    return;
                }
            }
        }
    }

    pub fn set_readout_nth(
        &mut self,
        nth: usize,
        new_label: &'static str,
        new_val: String,
        new_col: Option<[f32; 4]>,
    ) {
        if let Some(Item::Readout {
            label,
            value,
            color,
        }) = self
            .items
            .iter_mut()
            .filter(|it| matches!(it, Item::Readout { .. }))
            .nth(nth)
        {
            *label = new_label;
            *value = new_val;
            if let Some(c) = new_col {
                *color = c;
            }
        }
    }

    pub fn set_data_meter(
        &mut self,
        speed_txt: String,
        vol_txt: String,
        ratio: f32,
        new_col: Option<[f32; 4]>,
    ) {
        for item in &mut self.items {
            if let Item::DataMeter {
                speed_text,
                volume_text,
                fill_ratio,
                color,
            } = item
            {
                *speed_text = speed_txt;
                *volume_text = vol_txt;
                *fill_ratio = ratio;
                if let Some(c) = new_col {
                    *color = c;
                }
                return;
            }
        }
    }

    pub fn set_group_apps_label(&mut self, new_label: String) {
        for item in &mut self.items {
            if let Item::GroupAppsButton { label, .. } = item {
                *label = new_label;
                return;
            }
        }
    }

    pub fn take_group_apps_clicked(&mut self) -> bool {
        for item in &mut self.items {
            if let Item::GroupAppsButton { clicked, .. } = item {
                if *clicked {
                    *clicked = false;
                    return true;
                }
            }
        }
        false
    }

    pub fn slider(&self, label: &str) -> Option<f32> {
        self.items.iter().find_map(|item| match item {
            Item::Slider {
                label: l, value, ..
            } if *l == label => Some(*value),
            _ => None,
        })
    }

    pub fn text_input(&self, label: &str) -> Option<&str> {
        self.items.iter().find_map(|item| match item {
            Item::TextInput {
                label: l, value, ..
            } if *l == label => Some(value.as_str()),
            _ => None,
        })
    }

    pub fn set_text_input(&mut self, label: &str, new_val: String) {
        for item in &mut self.items {
            if let Item::TextInput { label: l, value, .. } = item {
                if *l == label {
                    *value = new_val;
                    return;
                }
            }
        }
    }

    pub fn combo_selected(&self, label: &str) -> Option<(usize, &'static str)> {
        self.items.iter().find_map(|item| match item {
            Item::Combo {
                label: l,
                options,
                selected,
            } if *l == label => Some((*selected, options.get(*selected).copied().unwrap_or(""))),
            _ => None,
        })
    }

    pub fn set_combo_selected(&mut self, label: &str, idx: usize) {
        for item in &mut self.items {
            if let Item::Combo {
                label: l,
                options,
                selected,
            } = item
            {
                if *l == label && idx < options.len() {
                    *selected = idx;
                    return;
                }
            }
        }
    }

    pub fn checkbox(&self, label: &str) -> Option<bool> {
        self.items.iter().find_map(|item| match item {
            Item::Checkbox { label: l, value } if *l == label => Some(*value),
            _ => None,
        })
    }

    pub fn set_wave(&mut self, wave: &[f32]) {
        self.set_wave_detailed(wave, wave, &[0.0; WAVE_SAMPLES], 0);
    }

    pub fn set_wave_detailed(
        &mut self,
        combined: &[f32],
        down: &[f32],
        up: &[f32],
        mode: u8,
    ) {
        for item in &mut self.items {
            if let Item::WaveGraph {
                values,
                down_values,
                up_values,
                mode: m,
                ..
            } = item
            {
                *m = mode;
                copy_wave_slice(values, combined);
                copy_wave_slice(down_values, down);
                copy_wave_slice(up_values, up);
            }
        }
    }

    /// Parses full proxy URLs (`http://user:pass@host:port`, `socks5://user:pass@host:port`,
    /// `user:pass@host:port`, or `host:port:user:pass`) if pasted into `Server:`, `User:`, or `Pass:`,
    /// or when the `[ Paste Proxy URL ]` button is clicked.
    pub fn normalize_proxy_fields(&mut self, ui: &Ui) {
        if self.kind != NodeKind::ProxyNode {
            return;
        }

        // 1. Check if user clicked the "[ Paste Proxy URL ]" button on this ProxyNode
        if self.take_group_apps_clicked() {
            if let Some(clip) = read_system_clipboard().or_else(|| ui.clipboard_text()) {
                let trimmed = clip.trim();
                if let Some((proto_idx, srv, usr, pwd)) = parse_proxy_url(trimmed) {
                    if let Some(idx) = proto_idx {
                        self.set_combo_selected("Type:", idx);
                    }
                    self.set_text_input("Server:", srv);
                    self.set_text_input("User:", usr);
                    self.set_text_input("Pass:", pwd);
                    return;
                } else if !trimmed.is_empty() {
                    self.set_text_input("Server:", trimmed.to_string());
                }
            }
        }

        // 2. Also auto-parse if the user pasted a full proxy URL via Ctrl+V into Server, User, or Pass
        for field in ["Server:", "User:", "Pass:"] {
            if let Some(raw) = self.text_input(field).map(|s| s.trim().to_string()) {
                if raw.contains("://") || raw.contains('@') || raw.matches(':').count() >= 3 {
                    if let Some((proto_idx, srv, usr, pwd)) = parse_proxy_url(&raw) {
                        if let Some(idx) = proto_idx {
                            self.set_combo_selected("Type:", idx);
                        }
                        self.set_text_input("Server:", srv);
                        if !usr.is_empty() {
                            self.set_text_input("User:", usr);
                        }
                        if !pwd.is_empty() {
                            self.set_text_input("Pass:", pwd);
                        }
                        break;
                    }
                }
            }
        }
    }

    pub fn declare(&mut self, ui: &Ui) {
        if self.kind == NodeKind::TrafficMonitor {
            self.title = self.probe_config.variant.header_title().to_string();
        }
        let content_h = self.content_height();
        let _id_token = ui.push_id_int(self.id);
        ng::node_begin(
            ui,
            self.id,
            &mut self.pos,
            self.width,
            content_h,
            &self.title,
            self.accent,
        );
        let header_min = ui.item_rect_min();

        let cfg = self.probe_config;
        let is_probe = self.kind == NodeKind::TrafficMonitor;
        for item in &mut self.items {
            if is_probe {
                match item {
                    Item::DataMeter { .. } if !cfg.show_meter => continue,
                    Item::WaveGraph { .. } if !cfg.show_wave => continue,
                    _ => {}
                }
            }
            item.declare(ui);
        }

        if is_probe {
            self.render_probe_header_controls(ui, header_min);
        }

        ng::node_end();
        self.normalize_proxy_fields(ui);
    }
}

fn copy_wave_slice(dst: &mut [f32; WAVE_SAMPLES], src: &[f32]) {
    let len = src.len().min(WAVE_SAMPLES);
    dst.fill(0.0);
    if len > 0 {
        let offset = WAVE_SAMPLES - len;
        dst[offset..].copy_from_slice(&src[src.len() - len..]);
    }
}
