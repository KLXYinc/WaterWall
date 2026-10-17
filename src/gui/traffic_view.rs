use imgui::{StyleColor, Ui};

use super::groups::{app_signature_color, render_app_group_selector};
use super::icons::IconManager;
use super::widgets::{
    draw_app_icon_or_badge, render_shared_filter_bar, show_app_hover_tooltip, truncate_str,
    SharedFilterState,
};
use crate::net::{
    format_bytes, format_speed, AppNetworkInfo, NetworkMonitor, NetworkSnapshot, HISTORY_LEN,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrafficMetric {
    Combined,
    DownloadOnly,
    UploadOnly,
}

#[derive(Default)]
pub struct TrafficViewState {
    pub metric: Option<TrafficMetric>,
    pub stacked_mode: bool,
}

pub fn render_traffic_monitor_view(
    state: &mut TrafficViewState,
    filter: &mut SharedFilterState,
    snap: &NetworkSnapshot,
    monitor: &NetworkMonitor,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    ui: &Ui,
) {
    render_shared_filter_bar(filter, snap, monitor, ui);

    ui.spacing();
    ui.separator();
    ui.spacing();

    let mut ranked_apps: Vec<&AppNetworkInfo> =
        snap.apps.iter().filter(|a| filter.matches_app(a)).collect();
    ranked_apps.sort_by(|a, b| {
        let ta = (a.total_downloaded + a.total_uploaded) / (1024 * 64);
        let tb = (b.total_downloaded + b.total_uploaded) / (1024 * 64);
        tb.cmp(&ta).then_with(|| a.first_seen_id.cmp(&b.first_seen_id))
    });

    let top_apps: Vec<&AppNetworkInfo> = ranked_apps.iter().copied().take(8).collect();
    let metric = state.metric.unwrap_or(TrafficMetric::Combined);

    let active_col = [0.15f32, 0.50, 0.85, 1.0];
    for (m, label) in [
        (TrafficMetric::Combined, " Total (IN+OUT) "),
        (TrafficMetric::DownloadOnly, " Download (IN) "),
        (TrafficMetric::UploadOnly, " Upload (OUT) "),
    ] {
        let _s = (metric == m).then(|| ui.push_style_color(StyleColor::Button, active_col));
        if ui.button(label) {
            state.metric = Some(m);
        }
        ui.same_line();
    }

    ui.same_line_with_spacing(0.0, 10.0);
    {
        let _s = (!state.stacked_mode).then(|| ui.push_style_color(StyleColor::Button, active_col));
        if ui.button(" Overlaid ") {
            state.stacked_mode = false;
        }
    }
    ui.same_line();
    {
        let _s = state.stacked_mode.then(|| ui.push_style_color(StyleColor::Button, active_col));
        if ui.button(" Stacked ") {
            state.stacked_mode = true;
        }
    }

    if let Some(sel_name) = filter.selected_app.clone() {
        ui.same_line_with_spacing(0.0, 14.0);
        render_app_group_selector(
            ui,
            "traffic_top",
            &sel_name,
            &mut filter.groups,
            &mut filter.new_group_name_buf,
        );
        ui.same_line();
        if ui.button(" [Flow Graph] ") {
            filter.request_flow_graph = true;
        }
    } else {
        ui.same_line_with_spacing(0.0, 14.0);
        ui.text_disabled("(Click any app card below to assign it to a Flow Group)");
    }

    ui.spacing();

    let avail = ui.content_region_avail();
    let chart_h = (avail[1] * 0.44).clamp(170.0, 290.0);
    draw_multi_app_colored_chart(
        ui,
        &top_apps,
        metric,
        state.stacked_mode,
        filter.selected_app.as_deref(),
        [avail[0].max(400.0), chart_h],
    );

    ui.spacing();
    draw_proportional_share_bar(ui, &top_apps, avail[0].max(400.0));
    ui.spacing();
    ui.separator();
    ui.spacing();

    render_top_apps_color_list(filter, &ranked_apps, icon_manager, gl, ui);
}

fn series_for_app(app: &AppNetworkInfo, metric: TrafficMetric) -> Vec<f32> {
    let d = if app.download_history.is_empty() {
        vec![0.0; HISTORY_LEN]
    } else {
        app.download_history.clone()
    };
    let u = if app.upload_history.is_empty() {
        vec![0.0; HISTORY_LEN]
    } else {
        app.upload_history.clone()
    };
    match metric {
        TrafficMetric::Combined => d.iter().zip(u.iter()).map(|(a, b)| a + b).collect(),
        TrafficMetric::DownloadOnly => d,
        TrafficMetric::UploadOnly => u,
    }
}

fn draw_multi_app_colored_chart(
    ui: &Ui,
    top_apps: &[&AppNetworkInfo],
    metric: TrafficMetric,
    stacked: bool,
    selected_app: Option<&str>,
    size: [f32; 2],
) {
    let pos = ui.cursor_screen_pos();
    let (w, h) = (size[0], size[1]);
    let p_min = pos;
    let p_max = [pos[0] + w, pos[1] + h];

    ui.invisible_button("##multi_app_chart", [w, h]);
    let is_hovered = ui.is_item_hovered();
    let mouse_pos = ui.io().mouse_pos;

    let app_series: Vec<(&AppNetworkInfo, [f32; 4], Vec<f32>)> = top_apps
        .iter()
        .map(|app| {
            let col = app_signature_color(&app.name, app.first_seen_id);
            (*app, col, series_for_app(app, metric))
        })
        .collect();

    let mut peak = 1024.0 * 8.0f32;
    if stacked {
        for idx in 0..HISTORY_LEN {
            let sum: f32 = app_series
                .iter()
                .map(|(_, _, s)| s.get(idx).copied().unwrap_or(0.0))
                .sum();
            peak = peak.max(sum);
        }
    } else {
        for (_, _, s) in &app_series {
            for &v in s {
                peak = peak.max(v);
            }
        }
    }
    peak *= 1.15;

    let (ix0, ix1) = (p_min[0] + 8.0, p_max[0] - 8.0);
    let (iy0, iy1) = (p_min[1] + 8.0, p_max[1] - 8.0);
    let (iw, ih) = ((ix1 - ix0).max(10.0), (iy1 - iy0).max(10.0));

    {
        let dl = ui.get_window_draw_list();
        dl.add_rect(p_min, p_max, [0.06f32, 0.07, 0.09, 0.98]).rounding(6.0).filled(true).build();
        dl.add_rect(p_min, p_max, [0.20f32, 0.25, 0.32, 0.90]).rounding(6.0).thickness(1.2).build();

        for r in 1..=3 {
            let gy = iy0 + ih * (r as f32 * 0.25);
            dl.add_line([ix0, gy], [ix1, gy], [1.0f32, 1.0, 1.0, 0.06]).build();
        }
        for c in 1..=5 {
            let gx = ix0 + iw * (c as f32 / 6.0);
            dl.add_line([gx, iy0], [gx, iy1], [1.0f32, 1.0, 1.0, 0.04]).build();
        }

        let step_x = iw / (HISTORY_LEN - 1) as f32;
        let mut accum_prev = vec![0.0f32; HISTORY_LEN];

        for (app, col, s) in &app_series {
            let is_dimmed = selected_app.is_some_and(|sel| !sel.eq_ignore_ascii_case(&app.name));
            let alpha_mul = if is_dimmed { 0.28 } else { 1.0 };
            let fill_c = [col[0], col[1], col[2], 0.26 * alpha_mul];
            let line_c = [col[0], col[1], col[2], 0.96 * alpha_mul];

            for i in 0..(HISTORY_LEN - 1) {
                let v0 = s.get(i).copied().unwrap_or(0.0);
                let v1 = s.get(i + 1).copied().unwrap_or(0.0);
                let base0 = if stacked { accum_prev[i] } else { 0.0 };
                let base1 = if stacked { accum_prev[i + 1] } else { 0.0 };
                let top0 = base0 + v0;
                let top1 = base1 + v1;

                let x0 = ix0 + i as f32 * step_x;
                let x1 = ix0 + (i + 1) as f32 * step_x;
                let y_base0 = iy1 - (base0 / peak).clamp(0.0, 1.0) * ih;
                let y_base1 = iy1 - (base1 / peak).clamp(0.0, 1.0) * ih;
                let y_top0 = iy1 - (top0 / peak).clamp(0.0, 1.0) * ih;
                let y_top1 = iy1 - (top1 / peak).clamp(0.0, 1.0) * ih;

                dl.add_triangle([x0, y_top0], [x1, y_top1], [x1, y_base1], fill_c).filled(true).build();
                dl.add_triangle([x0, y_top0], [x1, y_base1], [x0, y_base0], fill_c).filled(true).build();
                dl.add_line([x0, y_top0], [x1, y_top1], line_c)
                    .thickness(if is_dimmed { 1.3 } else { 2.2 })
                    .build();
            }

            if stacked {
                for (acc, &val) in accum_prev.iter_mut().zip(s.iter()) {
                    *acc += val;
                }
            }
        }

        dl.add_text(
            [ix0 + 6.0, iy0 + 4.0],
            [0.65f32, 0.72, 0.82, 0.95],
            format!("Scale Peak: {}", format_speed(peak as f64)),
        );

        let mut lx = ix1 - 10.0;
        for (app, col, _) in app_series.iter().take(5).rev() {
            let lbl = truncate_str(&app.display_name(), 16);
            let tw = ui.calc_text_size(&lbl)[0];
            lx -= tw + 22.0;
            if lx < ix0 + 180.0 {
                break;
            }
            dl.add_rect([lx, iy0 + 6.0], [lx + 10.0, iy0 + 16.0], *col)
                .rounding(2.0)
                .filled(true)
                .build();
            dl.add_text([lx + 14.0, iy0 + 4.0], [0.90f32, 0.93, 0.98, 1.0], &lbl);
        }

        if is_hovered {
            let rel_x = ((mouse_pos[0] - ix0) / iw).clamp(0.0, 1.0);
            let idx = ((rel_x * (HISTORY_LEN - 1) as f32).round() as usize).min(HISTORY_LEN - 1);
            let cx = ix0 + (idx as f32 / (HISTORY_LEN - 1) as f32) * iw;
            dl.add_line([cx, iy0], [cx, iy1], [1.0f32, 1.0, 1.0, 0.55]).build();
        }
    }

    if is_hovered {
        let rel_x = ((mouse_pos[0] - ix0) / iw).clamp(0.0, 1.0);
        let idx = ((rel_x * (HISTORY_LEN - 1) as f32).round() as usize).min(HISTORY_LEN - 1);
        let secs_ago = ((HISTORY_LEN - 1).saturating_sub(idx) as f32 * 0.8).round() as u32;
        let mut tip = format!("Time: -{}s ago\n------------------------", secs_ago);
        for (app, _, s) in &app_series {
            let v = s.get(idx).copied().unwrap_or(0.0) as f64;
            tip.push_str(&format!("\n{:<18} {}", truncate_str(&app.display_name(), 18), format_speed(v)));
        }
        ui.tooltip_text(&tip);
    }
}

fn draw_proportional_share_bar(ui: &Ui, top_apps: &[&AppNetworkInfo], width: f32) {
    let pos = ui.cursor_screen_pos();
    let h = 10.0;
    let total_all: u64 = top_apps
        .iter()
        .map(|a| (a.total_downloaded + a.total_uploaded).max(1))
        .sum::<u64>()
        .max(1);

    let dl = ui.get_window_draw_list();
    dl.add_rect(pos, [pos[0] + width, pos[1] + h], [0.12f32, 0.14, 0.18, 1.0])
        .rounding(3.0)
        .filled(true)
        .build();

    let mut cur_x = pos[0];
    for app in top_apps {
        let bytes = (app.total_downloaded + app.total_uploaded).max(1);
        let seg_w = (bytes as f32 / total_all as f32) * width;
        if seg_w >= 1.5 {
            let col = app_signature_color(&app.name, app.first_seen_id);
            dl.add_rect([cur_x, pos[1]], [cur_x + seg_w - 1.0, pos[1] + h], col)
                .filled(true)
                .build();
            cur_x += seg_w;
        }
    }
    ui.dummy([width, h + 2.0]);
}

fn render_top_apps_color_list(
    filter: &mut SharedFilterState,
    ranked_apps: &[&AppNetworkInfo],
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    ui: &Ui,
) {
    let avail = ui.content_region_avail();
    if let Some(_child) = ui
        .child_window("traffic_ranked_apps")
        .size([avail[0], avail[1].max(140.0)])
        .build(|| {
            let total_all: u64 = ranked_apps
                .iter()
                .map(|a| a.total_downloaded + a.total_uploaded)
                .sum::<u64>()
                .max(1);

            for (rank, app) in ranked_apps.iter().enumerate() {
                let is_sel = filter
                    .selected_app
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&app.name));
                let col = app_signature_color(&app.name, app.first_seen_id);
                let group = filter.groups.group_for_app(&app.name).clone();
                let row_pos = ui.cursor_screen_pos();
                let row_w = avail[0] - 12.0;
                let row_h = if is_sel { 72.0 } else { 38.0 };

                {
                    let dl = ui.get_window_draw_list();
                    let bg = if is_sel {
                        [col[0] * 0.18, col[1] * 0.18, col[2] * 0.22, 0.85]
                    } else {
                        [0.10f32, 0.11, 0.14, 0.88]
                    };
                    dl.add_rect(row_pos, [row_pos[0] + row_w, row_pos[1] + row_h], bg)
                        .rounding(5.0)
                        .filled(true)
                        .build();
                    dl.add_rect(row_pos, [row_pos[0] + 6.0, row_pos[1] + row_h], col)
                        .rounding(3.0)
                        .filled(true)
                        .build();
                }

                if ui
                    .selectable_config(format!("##tm_row_{}", app.pid))
                    .selected(is_sel)
                    .size([row_w, 34.0])
                    .build()
                {
                    filter.selected_app = if is_sel { None } else { Some(app.name.clone()) };
                }
                if ui.is_item_hovered() {
                    show_app_hover_tooltip(ui, app, &group.name);
                }

                draw_app_icon_or_badge(
                    ui,
                    icon_manager,
                    gl,
                    app,
                    [row_pos[0] + 14.0, row_pos[1] + 7.0],
                    22.0,
                );

                let bytes = app.total_downloaded + app.total_uploaded;
                let share_pct = (bytes as f64 / total_all as f64) * 100.0;

                {
                    let dl = ui.get_window_draw_list();
                    let rank_name = truncate_str(&format!("#{}  {}", rank + 1, app.display_name()), 24);
                    dl.add_text([row_pos[0] + 44.0, row_pos[1] + 9.0], col, &rank_name);

                    let grp_x = (row_w * 0.26).clamp(215.0, 310.0);
                    let grp_str = truncate_str(&format!("[{}]", group.name), 22);
                    dl.add_text([row_pos[0] + grp_x, row_pos[1] + 9.0], group.color, &grp_str);

                    let right_txt = format!("{} ({:.1}%)", format_bytes(bytes), share_pct);
                    let rw = ui.calc_text_size(&right_txt)[0];
                    let right_x = row_pos[0] + row_w - rw - 14.0;

                    let spd_x = (row_w * 0.48).clamp(380.0, 540.0);
                    if row_pos[0] + spd_x + 190.0 < right_x {
                        dl.add_text(
                            [row_pos[0] + spd_x, row_pos[1] + 9.0],
                            [0.65f32, 0.75, 0.86, 1.0],
                            format!(
                                "IN: {}   OUT: {}   ({} conns)",
                                format_speed(app.download_speed),
                                format_speed(app.upload_speed),
                                app.connections.len()
                            ),
                        );
                    }

                    dl.add_text([right_x, row_pos[1] + 9.0], [0.95f32, 0.97, 1.0, 1.0], &right_txt);
                }

                if is_sel {
                    let exe = if app.exe_path.is_empty() {
                        "(system / unknown path)"
                    } else {
                        &app.exe_path
                    };
                    let info_line = format!(
                        "Path: {}   ·   PIDs: {:?}   ·   Cmd: {}",
                        exe,
                        &app.pids[..app.pids.len().min(5)],
                        if app.cmdline.is_empty() { "-" } else { &app.cmdline }
                    );
                    let max_chars = ((row_w - 60.0) / 6.8).max(24.0) as usize;
                    ui.set_cursor_screen_pos([row_pos[0] + 44.0, row_pos[1] + 27.0]);
                    ui.text_disabled(truncate_str(&info_line, max_chars));

                    ui.set_cursor_screen_pos([row_pos[0] + 44.0, row_pos[1] + 45.0]);
                    render_app_group_selector(
                        ui,
                        &format!("tm_card_{}", app.pid),
                        &app.name,
                        &mut filter.groups,
                        &mut filter.new_group_name_buf,
                    );
                    ui.same_line();
                    if ui.button(format!("Route Group in Flow Graph##tm_fg_{}", app.pid)) {
                        filter.request_flow_graph = true;
                    }
                }

                ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 4.0]);
            }
        })
    {}
}
