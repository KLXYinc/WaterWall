use imgui::node_graph as ng;
use imgui::Ui;

use super::item::{Item, WAVE_SAMPLES};
use super::NodeKind;
use crate::gui::graphics::read_system_clipboard;

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
}

impl Node {
    pub fn new(kind: NodeKind, id: i32, pos: [f32; 2]) -> Self {
        Self {
            id,
            kind,
            title: kind.title().to_string(),
            bound_group_id: None,
            pos,
            width: kind.width(),
            accent: kind.accent(),
            items: kind.default_items(id),
        }
    }

    pub fn content_height(&self) -> f32 {
        self.items.iter().map(Item::height).sum()
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
        for item in &mut self.items {
            if let Item::WaveGraph { values, .. } = item {
                let len = wave.len().min(WAVE_SAMPLES);
                values.fill(0.0);
                let offset = WAVE_SAMPLES - len;
                values[offset..].copy_from_slice(&wave[wave.len() - len..]);
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
        for item in &mut self.items {
            item.declare(ui);
        }
        ng::node_end();
        self.normalize_proxy_fields(ui);
    }
}

/// Parses proxy strings in formats:
/// - `http://user:pass@host:port` / `https://user:pass@host:port` / `socks5://user:pass@host:port`
/// - `user:pass@host:port`
/// - `host:port:user:pass`
pub fn parse_proxy_url(raw: &str) -> Option<(Option<usize>, String, String, String)> {
    let mut s = raw.trim();
    if s.is_empty() {
        return None;
    }

    let mut proto_idx = None;
    if let Some((scheme, rest)) = s.split_once("://") {
        let sc = scheme.to_lowercase();
        proto_idx = match sc.as_str() {
            "http" | "https" => Some(1), // HTTP CONNECT
            "socks5" | "socks5h" | "socks" => Some(0), // SOCKS5
            "ss" | "shadowsocks" => Some(3),
            _ => None,
        };
        s = rest.trim_end_matches('/');
    } else {
        s = s.trim_end_matches('/');
    }

    // Format A: `user:pass@host:port` (split on the last `@` in case password contains special chars)
    if let Some((auth, host_port)) = s.rsplit_once('@') {
        let host_port = host_port.trim().to_string();
        if host_port.is_empty() {
            return None;
        }
        let (user, pass) = match auth.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (auth.to_string(), String::new()),
        };
        return Some((proto_idx, host_port, user, pass));
    }

    // Format B: `host:port:user:pass` (4 colon-separated parts)
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() == 4 && parts[1].parse::<u16>().is_ok() {
        let host_port = format!("{}:{}", parts[0], parts[1]);
        return Some((
            proto_idx,
            host_port,
            parts[2].to_string(),
            parts[3].to_string(),
        ));
    }

    // Format C: `scheme://host:port` without credentials
    if proto_idx.is_some() && s.contains(':') {
        return Some((proto_idx, s.to_string(), String::new(), String::new()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iproyal_proxy_url() {
        let input = "http://6Rnh55e5IfbFB38g:cJUBMuk8d9aKDp1v_country-de_session-1c3Xnf55_lifetime-168h@geo.iproyal.com:12321";
        let (proto, srv, user, pass) = parse_proxy_url(input).expect("should parse proxy URL");
        assert_eq!(proto, Some(1)); // HTTP CONNECT
        assert_eq!(srv, "geo.iproyal.com:12321");
        assert_eq!(user, "6Rnh55e5IfbFB38g");
        assert_eq!(
            pass,
            "cJUBMuk8d9aKDp1v_country-de_session-1c3Xnf55_lifetime-168h"
        );
    }
}
