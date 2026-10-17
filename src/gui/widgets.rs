use imgui::{StyleColor, Ui};

use super::flags::draw_country_flag;
use super::groups::{app_signature_color, AppGroupManager};
use super::icons::IconManager;
use crate::net::{
    format_bytes, format_speed, AppNetworkInfo, CountryCode, NetworkMonitor, NetworkSnapshot,
};

/// Safe UTF-8 character truncation (never panics on multi-byte characters).
pub fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let take_n = max_chars.saturating_sub(2).max(1);
        let prefix: String = s.chars().take(take_n).collect();
        format!("{}..", prefix)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeFilter {
    All,
    RemoteOnly,
    LocalOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortMode {
    StableOrder,
    HighestTraffic,
    ActiveSockets,
    Alphabetical,
}

impl SortMode {
    pub fn label(self) -> &'static str {
        match self {
            SortMode::StableOrder => "Stable (No Jump)",
            SortMode::HighestTraffic => "Top Bandwidth",
            SortMode::ActiveSockets => "Active Sockets",
            SortMode::Alphabetical => "Name (A-Z)",
        }
    }
}

/// Unified filter, selection, and group state shared across all views (DRY)
pub struct SharedFilterState {
    pub scope: ScopeFilter,
    pub sort_mode: SortMode,
    pub search_query: String,
    pub selected_app: Option<String>,
    pub selected_country: Option<CountryCode>,
    pub selected_protocol: Option<&'static str>,
    pub groups: AppGroupManager,
    pub new_group_name_buf: String,
}

impl Default for SharedFilterState {
    fn default() -> Self {
        Self {
            scope: ScopeFilter::All,
            sort_mode: SortMode::StableOrder,
            search_query: String::new(),
            selected_app: None,
            selected_country: None,
            selected_protocol: None,
            groups: AppGroupManager::new(),
            new_group_name_buf: String::new(),
        }
    }
}

impl SharedFilterState {
    pub fn matches_app(&self, app: &AppNetworkInfo) -> bool {
        match self.scope {
            ScopeFilter::All => {}
            ScopeFilter::RemoteOnly if !app.has_remote_connection() => return false,
            ScopeFilter::LocalOnly if !app.is_local_only() => return false,
            _ => {}
        }

        if !self.search_query.is_empty() {
            let q = self.search_query.to_lowercase();
            let name_hit = app.name.to_lowercase().contains(&q);
            let pid_hit = app.pid.to_string().contains(&q);
            let group_hit = self
                .groups
                .group_for_app(&app.name)
                .name
                .to_lowercase()
                .contains(&q);
            let conn_hit = app.connections.iter().any(|c| {
                c.remote_addr.to_string().contains(&q)
                    || c.domain
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains(&q))
            });
            if !name_hit && !pid_hit && !group_hit && !conn_hit {
                return false;
            }
        }

        true
    }
}

/// Renders the unified top filter bar (Scope, Sort, Search, Active Chips, Incognito, Freeze, Reset)
pub fn render_shared_filter_bar(
    filter: &mut SharedFilterState,
    snap: &NetworkSnapshot,
    monitor: &NetworkMonitor,
    ui: &Ui,
) {
    let total_apps = snap.apps.len();
    let remote_apps = snap.apps.iter().filter(|a| a.has_remote_connection()).count();
    let local_apps = snap.apps.iter().filter(|a| a.is_local_only()).count();

    let active_btn_col = [0.15f32, 0.50, 0.85, 1.0];

    for (scope, label) in [
        (ScopeFilter::All, format!(" All ({}) ", total_apps)),
        (ScopeFilter::RemoteOnly, format!(" Remote WAN ({}) ", remote_apps)),
        (ScopeFilter::LocalOnly, format!(" Local LAN ({}) ", local_apps)),
    ] {
        let is_sel = filter.scope == scope;
        let _s = is_sel.then(|| ui.push_style_color(StyleColor::Button, active_btn_col));
        if ui.button(&label) {
            filter.scope = scope;
        }
        ui.same_line();
    }

    ui.same_line_with_spacing(0.0, 10.0);
    ui.text_disabled("Order:");
    ui.same_line();
    if ui.button(&format!(" {} [v] ", filter.sort_mode.label())) {
        ui.open_popup("shared_sort_popup");
    }
    ui.popup("shared_sort_popup", || {
        for mode in [
            SortMode::StableOrder,
            SortMode::HighestTraffic,
            SortMode::ActiveSockets,
            SortMode::Alphabetical,
        ] {
            if ui.menu_item(mode.label()) {
                filter.sort_mode = mode;
            }
        }
    });

    ui.same_line_with_spacing(0.0, 10.0);
    ui.text_disabled("Search:");
    ui.same_line();
    ui.set_next_item_width(155.0);
    ui.input_text("##shared_search", &mut filter.search_query)
        .hint("App, IP, domain, group...")
        .build();

    if !filter.search_query.is_empty() {
        ui.same_line();
        if ui.button("Clear##clr_search") {
            filter.search_query.clear();
        }
    }

    if let Some(app_name) = filter.selected_app.clone() {
        ui.same_line_with_spacing(0.0, 8.0);
        let _c = ui.push_style_color(StyleColor::Button, [0.12f32, 0.48, 0.38, 0.95]);
        if ui.button(&format!(" App: {} [x] ", truncate_str(&app_name, 14))) {
            filter.selected_app = None;
        }
    }

    if let Some(cc) = filter.selected_country {
        ui.same_line_with_spacing(0.0, 6.0);
        let _c = ui.push_style_color(StyleColor::Button, [0.22f32, 0.38, 0.65, 0.95]);
        if ui.button(&format!(" {} [x] ", cc.code())) {
            filter.selected_country = None;
        }
    }

    if let Some(proto) = filter.selected_protocol {
        ui.same_line_with_spacing(0.0, 6.0);
        let _c = ui.push_style_color(StyleColor::Button, [0.45f32, 0.28, 0.65, 0.95]);
        if ui.button(&format!(" {} [x] ", proto)) {
            filter.selected_protocol = None;
        }
    }

    let avail_w = ui.content_region_avail()[0];
    if avail_w > 300.0 {
        ui.same_line_with_spacing(0.0, avail_w - 295.0);
    } else {
        ui.same_line();
    }

    let is_incog = monitor.is_incognito();
    {
        let _c = is_incog.then(|| ui.push_style_color(StyleColor::Button, [0.55f32, 0.25, 0.78, 1.0]));
        let lbl = if is_incog { " [Incognito: ON] " } else { " [Incognito] " };
        if ui.button(lbl) {
            monitor.toggle_incognito();
        }
    }

    ui.same_line();
    let is_paused = monitor.is_paused();
    {
        let _c = is_paused.then(|| ui.push_style_color(StyleColor::Button, [0.85f32, 0.48, 0.12, 1.0]));
        let label = if is_paused { " [FROZEN] " } else { " [Freeze] " };
        if ui.button(label) {
            monitor.toggle_pause();
        }
    }
    ui.same_line();
    if ui.button(" [Reset] ") {
        monitor.clear_history();
    }
}

/// Reusable helper to draw an application's real Linux icon or fallback signature badge.
pub fn draw_app_icon_or_badge(
    ui: &Ui,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    app: &AppNetworkInfo,
    pos: [f32; 2],
    size: f32,
) {
    let prev_cursor = ui.cursor_screen_pos();
    if let Some(tex_id) = icon_manager.get_or_load_icon(gl, &app.name, &app.exe_path) {
        ui.set_cursor_screen_pos(pos);
        imgui::Image::new(tex_id, [size, size]).build(ui);
        ui.set_cursor_screen_pos(prev_cursor);
    } else {
        let (code, _, _) = app.category_badge();
        let col = app_signature_color(&app.name, app.first_seen_id);
        let dl = ui.get_window_draw_list();
        dl.add_rect(pos, [pos[0] + size, pos[1] + size], col)
            .rounding(4.0)
            .filled(true)
            .build();
        let short = &code[..code.len().min(2)];
        let tw = ui.calc_text_size(short)[0];
        let tx = pos[0] + ((size - tw) * 0.5).max(1.0);
        let ty = pos[1] + ((size - 13.0) * 0.5).max(1.0);
        dl.add_text([tx, ty], [0.06f32, 0.07, 0.09, 1.0], short);
    }
}

/// Renders a dual-series shaded area mountain chart (Download + Upload) with hover inspection.
pub fn draw_dual_area_chart(
    ui: &Ui,
    id: &str,
    down_samples: &[f32],
    up_samples: &[f32],
    size: [f32; 2],
    show_time_axis: bool,
) {
    let pos = ui.cursor_screen_pos();
    let w = size[0].max(120.0);
    let h = size[1].max(42.0);
    let p_min = pos;
    let p_max = [pos[0] + w, pos[1] + h];

    ui.invisible_button(id, [w, h]);
    let is_hovered = ui.is_item_hovered();
    let mouse_pos = ui.io().mouse_pos;

    let max_down = down_samples.iter().copied().fold(0.0f32, f32::max);
    let max_up = up_samples.iter().copied().fold(0.0f32, f32::max);
    let peak = max_down.max(max_up).max(1024.0 * 4.0) * 1.15;

    let down_line_col = [0.15f32, 0.90, 0.78, 1.0];
    let down_fill_col = [0.15f32, 0.90, 0.78, 0.22];
    let up_line_col = [0.98f32, 0.45, 0.65, 0.95];
    let up_fill_col = [0.98f32, 0.45, 0.65, 0.18];

    let (inner_x0, inner_x1) = (p_min[0] + 6.0, p_max[0] - 6.0);
    let (inner_y0, inner_y1) = (p_min[1] + 6.0, p_max[1] - 6.0);
    let inner_w = (inner_x1 - inner_x0).max(10.0);
    let inner_h = (inner_y1 - inner_y0).max(10.0);

    {
        let dl = ui.get_window_draw_list();
        dl.add_rect(p_min, p_max, [0.07f32, 0.08, 0.10, 0.96]).rounding(5.0).filled(true).build();
        dl.add_rect(p_min, p_max, [0.20f32, 0.24, 0.30, 0.85]).rounding(5.0).thickness(1.0).build();

        for row in 1..=3 {
            let gy = inner_y0 + inner_h * (row as f32 * 0.25);
            dl.add_line([inner_x0, gy], [inner_x1, gy], [1.0f32, 1.0, 1.0, 0.06]).build();
        }

        let draw_series = |samples: &[f32], line_c: [f32; 4], fill_c: [f32; 4]| {
            let n = samples.len();
            if n < 2 {
                return;
            }
            let step_x = inner_w / (n - 1) as f32;
            for i in 0..(n - 1) {
                let v0 = (samples[i] / peak).clamp(0.0, 1.0);
                let v1 = (samples[i + 1] / peak).clamp(0.0, 1.0);
                let x0 = inner_x0 + i as f32 * step_x;
                let x1 = inner_x0 + (i + 1) as f32 * step_x;
                let y0 = inner_y1 - v0 * inner_h;
                let y1 = inner_y1 - v1 * inner_h;
                dl.add_triangle([x0, y0], [x1, y1], [x1, inner_y1], fill_c).filled(true).build();
                dl.add_triangle([x0, y0], [x1, inner_y1], [x0, inner_y1], fill_c).filled(true).build();
                dl.add_line([x0, y0], [x1, y1], line_c).thickness(2.0).build();
            }
        };

        draw_series(up_samples, up_line_col, up_fill_col);
        draw_series(down_samples, down_line_col, down_fill_col);

        dl.add_text(
            [inner_x0 + 4.0, inner_y0 + 2.0],
            [0.58f32, 0.65, 0.75, 0.90],
            &format!("Peak: {}", format_speed(peak as f64)),
        );

        let n = down_samples.len().max(up_samples.len());
        if is_hovered && n >= 2 {
            let rel_x = ((mouse_pos[0] - inner_x0) / inner_w).clamp(0.0, 1.0);
            let idx = ((rel_x * (n - 1) as f32).round() as usize).min(n - 1);
            let cx = inner_x0 + (idx as f32 / (n - 1) as f32) * inner_w;
            dl.add_line([cx, inner_y0], [cx, inner_y1], [1.0f32, 1.0, 1.0, 0.45]).build();
        }

        if show_time_axis {
            let ticks = ["-48s", "-36s", "-24s", "-12s", "Now (Live)"];
            let step = w / (ticks.len() - 1) as f32;
            for (i, tick) in ticks.iter().enumerate() {
                let tw = ui.calc_text_size(tick)[0];
                let tx = (p_min[0] + step * i as f32 - tw * 0.5).clamp(p_min[0], p_max[0] - tw);
                dl.add_text([tx, p_max[1] + 3.0], [0.52f32, 0.58, 0.66, 1.0], tick);
            }
        }
    }

    let n = down_samples.len().max(up_samples.len());
    if is_hovered && n >= 2 {
        let rel_x = ((mouse_pos[0] - inner_x0) / inner_w).clamp(0.0, 1.0);
        let idx = ((rel_x * (n - 1) as f32).round() as usize).min(n - 1);
        let secs_ago = ((n - 1).saturating_sub(idx) as f32 * 0.8).round() as u32;
        let dv = down_samples.get(idx).copied().unwrap_or(0.0) as f64;
        let uv = up_samples.get(idx).copied().unwrap_or(0.0) as f64;
        ui.tooltip_text(&format!(
            "Time: -{}s ago\nDownload (IN):  {}\nUpload (OUT):   {}",
            secs_ago,
            format_speed(dv),
            format_speed(uv)
        ));
    }

    if show_time_axis {
        ui.dummy([0.0, 16.0]);
    }
}

/// Renders a compact country summary row with a real graphical flag
pub fn draw_country_row(
    ui: &Ui,
    country: CountryCode,
    bytes: u64,
    sockets: usize,
    max_bytes: f32,
    width: f32,
    is_selected: bool,
) -> bool {
    let row_pos = ui.cursor_screen_pos();
    let row_h = 24.0;

    if is_selected {
        let dl = ui.get_window_draw_list();
        dl.add_rect(
            [row_pos[0], row_pos[1] - 1.0],
            [row_pos[0] + width - 8.0, row_pos[1] + row_h - 1.0],
            [0.15f32, 0.45, 0.75, 0.45],
        )
        .rounding(3.0)
        .filled(true)
        .build();
    }

    let clicked = ui
        .selectable_config(&format!("##country_sel_{}", country.code()))
        .selected(is_selected)
        .size([width - 10.0, row_h - 2.0])
        .build();

    draw_country_flag(ui, [row_pos[0] + 4.0, row_pos[1] + 3.0], country);

    let dl = ui.get_window_draw_list();
    let label = truncate_str(&format!("{} ({})", country.name(), sockets), 19);
    dl.add_text(
        [row_pos[0] + 28.0, row_pos[1] + 2.0],
        if is_selected { [0.30f32, 0.90, 1.0, 1.0] } else { [0.88f32, 0.91, 0.95, 1.0] },
        &label,
    );

    let b_str = format_bytes(bytes);
    let bw = ui.calc_text_size(&b_str)[0];
    let bx = (row_pos[0] + width - bw - 14.0).max(row_pos[0] + 115.0);
    dl.add_text([bx, row_pos[1] + 2.0], [0.65f32, 0.72, 0.80, 1.0], &b_str);

    let ratio = (bytes as f32 / max_bytes.max(1.0)).clamp(0.04, 1.0);
    let bar_w = (width - 38.0).max(10.0);
    dl.add_rect(
        [row_pos[0] + 28.0, row_pos[1] + 18.0],
        [row_pos[0] + 28.0 + bar_w * ratio, row_pos[1] + 20.0],
        [0.25f32, 0.75, 0.95, 0.85],
    )
    .filled(true)
    .build();

    ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h]);
    clicked
}
