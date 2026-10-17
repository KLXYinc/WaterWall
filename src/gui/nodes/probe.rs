use imgui::{StyleColor, Ui};

use super::item::{WAVE_ROW_H, WAVE_SAMPLES};
use super::Node;
use crate::utils::format_speed;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeVariant {
    BandwidthWave = 0,
    SplitInOut = 1,
    FlowEndpoints = 2,
    SocketTelemetry = 3,
}

impl ProbeVariant {
    pub const ALL: [ProbeVariant; 4] = [
        ProbeVariant::BandwidthWave,
        ProbeVariant::SplitInOut,
        ProbeVariant::FlowEndpoints,
        ProbeVariant::SocketTelemetry,
    ];

    pub fn from_index(idx: usize) -> Self {
        match idx % 4 {
            0 => Self::BandwidthWave,
            1 => Self::SplitInOut,
            2 => Self::FlowEndpoints,
            _ => Self::SocketTelemetry,
        }
    }

    pub fn next(self) -> Self {
        Self::from_index(self as usize + 1)
    }

    pub fn badge(self) -> &'static str {
        match self {
            Self::BandwidthWave => "BW",
            Self::SplitInOut => "I/O",
            Self::FlowEndpoints => "APP",
            Self::SocketTelemetry => "SCK",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::BandwidthWave => "Bandwidth & Waveform",
            Self::SplitInOut => "Split IN / OUT Inspector",
            Self::FlowEndpoints => "Top Apps & Endpoints",
            Self::SocketTelemetry => "Socket & Protocol Stats",
        }
    }

    pub fn header_title(self) -> &'static str {
        match self {
            Self::BandwidthWave => "Probe: Bandwidth",
            Self::SplitInOut => "Probe: Split IN/OUT",
            Self::FlowEndpoints => "Probe: Apps & Hosts",
            Self::SocketTelemetry => "Probe: Socket Stats",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeWaveChannel {
    Combined = 0,
    DownloadOnly = 1,
    UploadOnly = 2,
}

impl ProbeWaveChannel {
    pub fn from_index(idx: usize) -> Self {
        match idx % 3 {
            0 => Self::Combined,
            1 => Self::DownloadOnly,
            _ => Self::UploadOnly,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Combined => "Combined (IN + OUT)",
            Self::DownloadOnly => "Download Only (IN)",
            Self::UploadOnly => "Upload Only (OUT)",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProbeConfig {
    pub variant: ProbeVariant,
    pub wave_channel: ProbeWaveChannel,
    pub show_meter: bool,
    pub show_wave: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            variant: ProbeVariant::BandwidthWave,
            wave_channel: ProbeWaveChannel::Combined,
            show_meter: true,
            show_wave: true,
        }
    }
}

impl Node {
    pub(super) fn render_probe_header_controls(&mut self, ui: &Ui, header_min: [f32; 2]) {
        let prev_cursor = ui.cursor_screen_pos();
        let btn_y = header_min[1] + 3.5;
        let cycle_x = header_min[0] + self.width - 72.0;
        let menu_x = header_min[0] + self.width - 48.0;

        let _bg = ui.push_style_color(StyleColor::Button, [0.22f32, 0.16, 0.34, 0.95]);
        let _hv = ui.push_style_color(StyleColor::ButtonHovered, [0.36f32, 0.24, 0.54, 1.0]);
        let _tx = ui.push_style_color(StyleColor::Text, [0.94f32, 0.88, 1.0, 1.0]);

        ui.set_cursor_screen_pos([cycle_x, btn_y]);
        if ui.button_with_size("<>##probe_cycle", [22.0, 19.0]) {
            self.probe_config.variant = self.probe_config.variant.next();
            self.title = self.probe_config.variant.header_title().to_string();
        }
        if ui.is_item_hovered() {
            ui.tooltip_text("Click to cycle Live Traffic Probe variant");
        }

        ui.set_cursor_screen_pos([menu_x, btn_y]);
        let badge_lbl = format!("{} v##probe_cfg_btn", self.probe_config.variant.badge());
        if ui.button_with_size(badge_lbl, [43.0, 19.0]) {
            ui.open_popup("probe_cfg_popup");
        }
        if ui.is_item_hovered() {
            ui.tooltip_text("Configure Live Traffic Probe Variant & Display Options");
        }
        drop(_tx);
        drop(_hv);
        drop(_bg);

        ui.popup("probe_cfg_popup", || {
            ui.text_colored([0.82f32, 0.58, 0.98, 1.0], "Live Traffic Probe Variant");
            ui.separator();
            for v in ProbeVariant::ALL {
                let is_cur = self.probe_config.variant == v;
                ui.text_colored(
                    if is_cur {
                        [0.25f32, 0.94, 0.72, 1.0]
                    } else {
                        [0.55f32, 0.62, 0.72, 1.0]
                    },
                    if is_cur { "[*]" } else { "[ ]" },
                );
                ui.same_line();
                if ui.menu_item(format!("[{}] {}", v.badge(), v.title())) {
                    self.probe_config.variant = v;
                    self.title = v.header_title().to_string();
                }
            }

            ui.separator();
            ui.text_colored([0.82f32, 0.58, 0.98, 1.0], "Waveform Channel");
            for ch in [
                ProbeWaveChannel::Combined,
                ProbeWaveChannel::DownloadOnly,
                ProbeWaveChannel::UploadOnly,
            ] {
                let is_cur = self.probe_config.wave_channel == ch;
                ui.text_colored(
                    if is_cur {
                        [0.25f32, 0.94, 0.72, 1.0]
                    } else {
                        [0.55f32, 0.62, 0.72, 1.0]
                    },
                    if is_cur { "(*)" } else { "( )" },
                );
                ui.same_line();
                if ui.menu_item(ch.label()) {
                    self.probe_config.wave_channel = ch;
                }
            }

            ui.separator();
            ui.text_colored([0.82f32, 0.58, 0.98, 1.0], "Display Sections");
            ui.checkbox("Show Volume Meter", &mut self.probe_config.show_meter);
            ui.checkbox("Show Waveform Graph", &mut self.probe_config.show_wave);
        });

        ui.set_cursor_screen_pos(prev_cursor);
    }
}

pub(super) fn draw_detailed_node_wave(
    ui: &Ui,
    row: [f32; 4],
    combined: &[f32; WAVE_SAMPLES],
    down: &[f32; WAVE_SAMPLES],
    up: &[f32; WAVE_SAMPLES],
    mode: u8,
    accent: [f32; 4],
) {
    let (x0, y0, w, h) = (row[0], row[1], row[2].max(80.0), WAVE_ROW_H - 2.0);
    let (p_min, p_max) = ([x0, y0], [x0 + w, y0 + h]);

    ui.invisible_button("##node_wave_btn", [w, h]);
    let is_hovered = ui.is_item_hovered();
    let mouse_pos = ui.io().mouse_pos;

    let (ix0, ix1, iy0, iy1) = (x0 + 4.0, x0 + w - 4.0, y0 + 15.0, y0 + h - 4.0);
    let (iw, ih) = ((ix1 - ix0).max(10.0), (iy1 - iy0).max(10.0));

    let peak_comb = combined.iter().copied().fold(0.0f32, f32::max);
    let peak_down = down.iter().copied().fold(0.0f32, f32::max);
    let peak_up = up.iter().copied().fold(0.0f32, f32::max);
    let raw_peak = match mode {
        1 => peak_down,
        2 => peak_up,
        _ => peak_comb.max(peak_down).max(peak_up),
    };
    let scale = (raw_peak * 1.18).max(1024.0);

    let active_series = match mode {
        1 => down,
        2 => up,
        _ => combined,
    };
    let avg_val: f32 = active_series.iter().copied().sum::<f32>() / WAVE_SAMPLES as f32;
    let (live_down, live_up) = (down[WAVE_SAMPLES - 1], up[WAVE_SAMPLES - 1]);
    let (in_col, out_col) = ([0.14f32, 0.92, 0.78, 1.0], [0.98f32, 0.44, 0.66, 1.0]);

    let dl = ui.get_window_draw_list();
    dl.add_rect(p_min, p_max, [0.055f32, 0.063, 0.082, 0.96]).rounding(5.0).filled(true).build();
    dl.add_rect(p_min, [x0 + w, y0 + 14.0], [0.09f32, 0.11, 0.15, 0.90]).rounding(5.0).filled(true).build();
    dl.add_rect(p_min, p_max, [accent[0] * 0.45, accent[1] * 0.45, accent[2] * 0.50, 0.65]).rounding(5.0).thickness(1.0).build();

    for r in 1..=3 {
        let gy = iy0 + ih * (r as f32 * 0.25);
        dl.add_line([ix0, gy], [ix1, gy], [1.0f32, 1.0, 1.0, 0.055]).build();
    }
    for c in 1..=4 {
        let gx = ix0 + iw * (c as f32 * 0.20);
        dl.add_line([gx, iy0], [gx, iy1], [1.0f32, 1.0, 1.0, 0.045]).build();
    }

    let step_x = iw / (WAVE_SAMPLES - 1) as f32;
    let draw_curve = |series: &[f32; WAVE_SAMPLES], col: [f32; 4], fill_alpha: f32, line_w: f32| {
        let fill_top = [col[0], col[1], col[2], fill_alpha];
        let fill_bot = [col[0] * 0.5, col[1] * 0.5, col[2] * 0.5, fill_alpha * 0.25];
        let glow_col = [col[0], col[1], col[2], 0.22];
        let (mut peak_idx, mut peak_v) = (0usize, 0.0f32);

        for i in 0..(WAVE_SAMPLES - 1) {
            let v0 = (series[i] / scale).clamp(0.0, 1.0);
            let v1 = (series[i + 1] / scale).clamp(0.0, 1.0);
            if series[i] >= peak_v {
                peak_v = series[i];
                peak_idx = i;
            }
            let (x_a, x_b) = (ix0 + i as f32 * step_x, ix0 + (i + 1) as f32 * step_x);
            let (y_a, y_b) = (iy1 - v0 * ih, iy1 - v1 * ih);
            let (y_mid_a, y_mid_b) = ((y_a + iy1) * 0.5, (y_b + iy1) * 0.5);

            if v0 > 0.002 || v1 > 0.002 {
                dl.add_triangle([x_a, y_a], [x_b, y_b], [x_b, y_mid_b], fill_top).filled(true).build();
                dl.add_triangle([x_a, y_a], [x_b, y_mid_b], [x_a, y_mid_a], fill_top).filled(true).build();
                dl.add_triangle([x_a, y_mid_a], [x_b, y_mid_b], [x_b, iy1], fill_bot).filled(true).build();
                dl.add_triangle([x_a, y_mid_a], [x_b, iy1], [x_a, iy1], fill_bot).filled(true).build();
                dl.add_line([x_a, y_a], [x_b, y_b], glow_col).thickness(line_w + 2.2).build();
            }
            dl.add_line([x_a, y_a], [x_b, y_b], col).thickness(line_w).build();
        }
        if series[WAVE_SAMPLES - 1] >= peak_v {
            peak_v = series[WAVE_SAMPLES - 1];
            peak_idx = WAVE_SAMPLES - 1;
        }
        let last_v = (series[WAVE_SAMPLES - 1] / scale).clamp(0.0, 1.0);
        let head_pt = [ix1, iy1 - last_v * ih];
        if series[WAVE_SAMPLES - 1] >= 1.0 {
            dl.add_circle(head_pt, 3.6, [col[0], col[1], col[2], 0.35]).filled(true).build();
            dl.add_circle(head_pt, 2.0, [1.0f32, 1.0, 1.0, 0.95]).filled(true).build();
        }
        if peak_v >= 16.0 {
            let pk_x = ix0 + peak_idx as f32 * step_x;
            let pk_y = iy1 - (peak_v / scale).clamp(0.0, 1.0) * ih;
            dl.add_circle([pk_x, pk_y], 2.2, [1.0f32, 0.92, 0.35, 0.95]).filled(true).build();
        }
    };

    match mode {
        1 => draw_curve(down, in_col, 0.32, 1.9),
        2 => draw_curve(up, out_col, 0.32, 1.9),
        _ => {
            if peak_down > 0.0 || peak_up > 0.0 {
                draw_curve(up, out_col, 0.24, 1.5);
                draw_curve(down, in_col, 0.28, 1.8);
            } else {
                draw_curve(combined, accent, 0.28, 1.8);
            }
        }
    }

    if avg_val >= 8.0 {
        let avg_y = iy1 - (avg_val / scale).clamp(0.02, 0.98) * ih;
        dl.add_line([ix0, avg_y], [ix1, avg_y], [0.95f32, 0.85, 0.35, 0.28]).thickness(1.0).build();
    }

    let pk_txt = format!("Pk {}", format_speed(raw_peak as f64));
    dl.add_text([x0 + 5.0, y0 + 1.0], [0.68f32, 0.76, 0.88, 0.95], &pk_txt);

    let right_hud = match mode {
        1 => format!("▼ {}", format_speed(live_down as f64)),
        2 => format!("▲ {}", format_speed(live_up as f64)),
        _ => format!("▼{} ▲{}", format_speed(live_down as f64), format_speed(live_up as f64)),
    };
    let rw = ui.calc_text_size(&right_hud)[0];
    let rx = (x0 + w - rw - 5.0).max(x0 + 78.0);
    dl.add_text([rx, y0 + 1.0], if mode == 2 { out_col } else { in_col }, &right_hud);

    if is_hovered {
        let rel_x = ((mouse_pos[0] - ix0) / iw).clamp(0.0, 1.0);
        let idx = ((rel_x * (WAVE_SAMPLES - 1) as f32).round() as usize).min(WAVE_SAMPLES - 1);
        let cx = ix0 + idx as f32 * step_x;
        dl.add_line([cx, iy0], [cx, iy1], [1.0f32, 1.0, 1.0, 0.55]).thickness(1.0).build();

        let (dv, uv) = (down[idx], up[idx]);
        let (dy, uy) = (iy1 - (dv / scale).clamp(0.0, 1.0) * ih, iy1 - (uv / scale).clamp(0.0, 1.0) * ih);
        dl.add_circle([cx, dy], 3.0, in_col).filled(true).build();
        dl.add_circle([cx, uy], 3.0, out_col).filled(true).build();

        let secs_ago = ((WAVE_SAMPLES - 1).saturating_sub(idx) as f32 * 0.8).round() as u32;
        ui.tooltip_text(format!(
            "Sample: -{}s ago\n\
             ----------------------------------\n\
             Download (IN):  ▼ {}\n\
             Upload (OUT):   ▲ {}\n\
             Combined:       {}\n\
             ----------------------------------\n\
             Window Peak:    {}  |  Avg: {}",
            secs_ago,
            format_speed(dv as f64),
            format_speed(uv as f64),
            format_speed((dv + uv).max(combined[idx]) as f64),
            format_speed(raw_peak as f64),
            format_speed(avg_val as f64)
        ));
    }
}
