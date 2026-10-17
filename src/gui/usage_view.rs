use std::collections::HashMap;

use imgui::Ui;

use super::flags::draw_flag_and_code;
use super::groups::{
    app_signature_color, render_app_group_selector, render_group_apps_editor_popup,
};
use super::icons::IconManager;
use super::widgets::{
    draw_app_icon_or_badge, draw_country_row, render_selected_app_details,
    render_shared_filter_bar, show_app_hover_tooltip, truncate_str, SharedFilterState,
};
use crate::net::{
    format_bytes, format_speed, is_remote_ip, AppNetworkInfo, CountryCode, HostRecord,
    NetworkMonitor, NetworkSnapshot, ProtocolRecord,
};

pub fn render_usage_view(
    filter: &mut SharedFilterState,
    snapshot: &NetworkSnapshot,
    monitor: &NetworkMonitor,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    ui: &Ui,
) {
    render_shared_filter_bar(filter, snapshot, monitor, ui);
    ui.spacing();
    ui.separator();
    ui.spacing();

    let avail = ui.content_region_avail();
    let body_h = avail[1].max(250.0);
    let left_w = 252.0;
    let col_w = ((avail[0].max(800.0) - left_w - 24.0).max(480.0) / 3.0).max(150.0);

    render_left_analytics_panel(filter, snapshot, icon_manager, gl, left_w, body_h, ui);
    ui.same_line();
    render_usage_apps_column(filter, &snapshot.apps, icon_manager, gl, col_w, body_h, ui);
    ui.same_line();
    render_usage_hosts_column(filter, &snapshot.hosts, col_w, body_h, ui);
    ui.same_line();
    render_usage_protocols_column(filter, &snapshot.protocols, col_w, body_h, ui);
}

fn render_left_analytics_panel(
    filter: &mut SharedFilterState,
    snap: &NetworkSnapshot,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui.child_window("usage_left_panel").size([width, height]).build(|| {
        let pos = ui.cursor_screen_pos();
        let (total_in, total_out, down_spd, up_spd, center_label, ext_ratio, sel_app_obj) =
            match &filter.selected_app {
                Some(app_name) => {
                    let matching: Vec<&AppNetworkInfo> = snap
                        .apps
                        .iter()
                        .filter(|a| a.name.eq_ignore_ascii_case(app_name))
                        .collect();
                    let down: u64 = matching.iter().map(|a| a.total_downloaded).sum();
                    let up: u64 = matching.iter().map(|a| a.total_uploaded).sum();
                    let d_spd: f64 = matching.iter().map(|a| a.download_speed).sum();
                    let u_spd: f64 = matching.iter().map(|a| a.upload_speed).sum();
                    let (mut rem, mut tot) = (0usize, 0usize);
                    for a in &matching {
                        for c in &a.connections {
                            tot += 1;
                            if c.remote_addr.port() != 0 && is_remote_ip(&c.remote_addr.ip()) {
                                rem += 1;
                            }
                        }
                    }
                    let ratio = if tot > 0 { (rem as f32 / tot as f32).clamp(0.05, 0.95) } else { 0.5 };
                    (down, up, d_spd, u_spd, app_name.clone(), ratio, matching.first().copied())
                }
                None => {
                    let down = snap.apps.iter().map(|a| a.total_downloaded).sum::<u64>().max(snap.session_total_download);
                    let up = snap.apps.iter().map(|a| a.total_uploaded).sum::<u64>().max(snap.session_total_upload);
                    let wl = (snap.session_wan_bytes + snap.session_lan_bytes).max(1);
                    let ratio = (snap.session_wan_bytes as f32 / wl as f32).clamp(0.15, 0.92);
                    (down, up, snap.system_download_speed, snap.system_upload_speed, "All Traffic".to_string(), ratio, None)
                }
            };

        let in_ratio = (total_in as f32 / (total_in + total_out).max(1) as f32).clamp(0.05, 0.95);
        let (center_x, center_y, radius, thickness) = (pos[0] + width * 0.5, pos[1] + 60.0, 48.0, 11.0);
        let (in_color, out_color) = ([0.15f32, 0.90, 0.78, 1.0], [0.98f32, 0.45, 0.65, 1.0]);

        {
            let dl = ui.get_window_draw_list();
            dl.add_circle([center_x, center_y], radius, [0.14f32, 0.16, 0.20, 1.0]).thickness(thickness).num_segments(64).build();
            let (segments, in_segments, start) = (64, (64.0 * in_ratio) as usize, -std::f32::consts::FRAC_PI_2);
            for i in 0..segments {
                let a0 = start + (i as f32 / segments as f32) * std::f32::consts::TAU;
                let a1 = start + ((i + 1) as f32 / segments as f32) * std::f32::consts::TAU;
                dl.add_line(
                    [center_x + radius * a0.cos(), center_y + radius * a0.sin()],
                    [center_x + radius * a1.cos(), center_y + radius * a1.sin()],
                    if i < in_segments { in_color } else { out_color },
                )
                .thickness(thickness)
                .build();
            }
            let total_str = format_bytes(total_in + total_out);
            let tw = ui.calc_text_size(&total_str)[0];
            dl.add_text([center_x - tw * 0.5, center_y - 11.0], [0.96f32, 0.97, 0.99, 1.0], &total_str);
            let sub_cut = truncate_str(&center_label, 14);
            let sw = ui.calc_text_size(&sub_cut)[0];
            dl.add_text([center_x - sw * 0.5, center_y + 5.0], [0.55f32, 0.68, 0.82, 1.0], &sub_cut);
        }

        let label_y = pos[1] + 120.0;
        ui.set_cursor_screen_pos([pos[0] + 10.0, label_y]);
        ui.text_colored(in_color, format!("IN:  {}", format_bytes(total_in)));
        ui.set_cursor_screen_pos([pos[0] + 10.0, label_y + 15.0]);
        ui.text_disabled(format!("Live: {}", format_speed(down_spd)));

        ui.set_cursor_screen_pos([pos[0] + width * 0.52, label_y]);
        ui.text_colored(out_color, format!("OUT: {}", format_bytes(total_out)));
        ui.set_cursor_screen_pos([pos[0] + width * 0.52, label_y + 15.0]);
        ui.text_disabled(format!("Live: {}", format_speed(up_spd)));

        let wan_y = label_y + 34.0;
        ui.set_cursor_screen_pos([pos[0] + 10.0, wan_y]);
        let wan_pct = (ext_ratio * 100.0).round() as u32;
        ui.text_disabled(format!("WAN {}%  /  LAN {}%", wan_pct, 100u32.saturating_sub(wan_pct)));
        {
            let dl = ui.get_window_draw_list();
            let (bx, by, bw) = (pos[0] + 10.0, wan_y + 15.0, width - 24.0);
            dl.add_rect([bx, by], [bx + bw, by + 5.0], [0.22f32, 0.25, 0.32, 1.0]).rounding(2.0).filled(true).build();
            dl.add_rect([bx, by], [bx + bw * ext_ratio, by + 5.0], [0.20f32, 0.78, 0.95, 1.0]).rounding(2.0).filled(true).build();
        }
        ui.set_cursor_screen_pos([pos[0] + 8.0, wan_y + 24.0]);

        // When an app is selected, show its Path & Info, Group selector & "Show / Edit Group Apps"
        if let Some(app) = sel_app_obj {
            ui.separator();
            let grp_name = filter.groups.group_for_app(&app.name).name.clone();
            render_selected_app_details(ui, app, &grp_name, width);
            ui.spacing();
            render_app_group_selector(ui, "usage_left", &app.name, &mut filter.groups, &mut filter.new_group_name_buf);
            let cur_gid = filter.groups.group_id_for_app(&app.name);
            let pop_id = format!("usage_grp_apps_pop_{}", cur_gid);
            if ui.button(" Show / Edit Group Apps ") {
                ui.open_popup(&pop_id);
            }
            render_group_apps_editor_popup(
                ui,
                &pop_id,
                cur_gid,
                &mut filter.groups,
                &snap.apps,
                icon_manager,
                gl,
            );
        }

        ui.spacing();
        ui.separator();
        ui.text_colored([0.92f32, 0.95, 0.99, 1.0], "Countries (Click to Filter)");
        ui.separator();

        let mut country_map: HashMap<CountryCode, (u64, usize, u64)> = HashMap::new();
        for h in &snap.hosts {
            if !h.matches_app(filter.selected_app.as_deref()) || !filter.matches_scope(h.is_local) {
                continue;
            }
            let entry = country_map.entry(h.country_code).or_insert((0, 0, h.first_seen_id));
            entry.0 = entry.0.saturating_add(h.bytes_for_app(filter.selected_app.as_deref()));
            entry.1 += h.sockets_for_app(filter.selected_app.as_deref());
            entry.2 = entry.2.min(h.first_seen_id);
        }

        let mut countries: Vec<(CountryCode, u64, usize, u64)> =
            country_map.into_iter().map(|(cc, (b, s, id))| (cc, b, s, id)).collect();
        countries.sort_by_key(|a| (a.0 == CountryCode::LOCAL, a.3));
        let max_c_bytes = countries.iter().map(|c| c.1).max().unwrap_or(1) as f32;

        for (cc, bytes, sockets, _) in countries {
            let is_sel = filter.selected_country == Some(cc);
            if draw_country_row(ui, cc, bytes, sockets, max_c_bytes, width, is_sel) {
                filter.selected_country = if is_sel { None } else { Some(cc) };
            }
        }
    }) {}
}

fn render_usage_apps_column(
    filter: &mut SharedFilterState,
    apps: &[AppNetworkInfo],
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui.child_window("usage_col_apps").size([width, height]).build(|| {
        let mut filtered: Vec<&AppNetworkInfo> = apps.iter().filter(|a| filter.matches_app(a)).collect();
        filter.sort_apps(&mut filtered);

        ui.text_colored([0.96f32, 0.97, 0.99, 1.0], format!("Applications ({})", filtered.len()));
        ui.separator();

        let total_all_bytes: u64 = filtered.iter().map(|a| a.total_downloaded + a.total_uploaded).sum();
        let max_data = filtered.iter().map(|a| a.total_downloaded + a.total_uploaded).max().unwrap_or(1).max(1) as f32;
        let row_h = 34.0;

        let is_all_selected = filter.selected_app.is_none();
        let all_pos = ui.cursor_screen_pos();
        if is_all_selected {
            let dl = ui.get_window_draw_list();
            dl.add_rect([all_pos[0], all_pos[1] - 2.0], [all_pos[0] + width - 10.0, all_pos[1] + row_h - 2.0], [0.10f32, 0.45, 0.35, 0.50]).rounding(4.0).filled(true).build();
        }
        if ui.selectable_config("##sel_usage_all").selected(is_all_selected).size([width - 12.0, row_h - 4.0]).build() {
            filter.selected_app = None;
        }
        {
            let dl = ui.get_window_draw_list();
            dl.add_rect([all_pos[0] + 4.0, all_pos[1] + 3.0], [all_pos[0] + 24.0, all_pos[1] + 23.0], [0.15f32, 0.55, 0.90, 0.95]).rounding(4.0).filled(true).build();
            dl.add_text([all_pos[0] + 6.0, all_pos[1] + 6.0], [1.0f32, 1.0, 1.0, 1.0], "ALL");
            dl.add_text([all_pos[0] + 30.0, all_pos[1] + 4.0], if is_all_selected { [0.20f32, 0.95, 0.75, 1.0] } else { [0.96f32, 0.97, 0.99, 1.0] }, "All Applications");
            let all_str = format_bytes(total_all_bytes);
            let aw = ui.calc_text_size(&all_str)[0];
            dl.add_text([(all_pos[0] + width - aw - 18.0).max(all_pos[0] + 130.0), all_pos[1] + 4.0], [0.75f32, 0.80, 0.88, 1.0], &all_str);
        }
        ui.set_cursor_screen_pos([all_pos[0], all_pos[1] + row_h]);
        ui.separator();

        for app in filtered {
            let row_pos = ui.cursor_screen_pos();
            let total_bytes = app.total_downloaded + app.total_uploaded;
            let sig_col = app_signature_color(&app.name, app.first_seen_id);
            let is_selected = filter.selected_app.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&app.name));

            if is_selected {
                let dl = ui.get_window_draw_list();
                dl.add_rect([row_pos[0], row_pos[1] - 2.0], [row_pos[0] + width - 10.0, row_pos[1] + row_h - 2.0], [0.10f32, 0.45, 0.35, 0.50]).rounding(4.0).filled(true).build();
            }
            if ui.selectable_config(format!("##sel_usage_app_{}", app.pid)).selected(is_selected).size([width - 12.0, row_h - 4.0]).build() {
                filter.selected_app = if is_selected { None } else { Some(app.name.clone()) };
            }
            if ui.is_item_hovered() {
                let grp = filter.groups.group_for_app(&app.name);
                show_app_hover_tooltip(ui, app, &grp.name);
            }
            draw_app_icon_or_badge(ui, icon_manager, gl, app, [row_pos[0] + 4.0, row_pos[1] + 3.0], 20.0);

            let max_chars = ((width - 105.0) / 7.2).max(10.0) as usize;
            let name_cut = truncate_str(&app.display_name(), max_chars);
            {
                let dl = ui.get_window_draw_list();
                dl.add_circle([row_pos[0] + 32.0, row_pos[1] + 9.0], 3.2, sig_col).filled(true).build();
                dl.add_text([row_pos[0] + 40.0, row_pos[1] + 2.0], if is_selected { [0.20f32, 0.95, 0.75, 1.0] } else { [0.96f32, 0.97, 0.99, 1.0] }, &name_cut);
                let grp = filter.groups.group_for_app(&app.name);
                let sub_raw = if grp.id != 0 { format!("{} conns · [{}]", app.connections.len(), grp.name) } else { format!("{} conns", app.connections.len()) };
                let sub_info = truncate_str(&sub_raw, ((width - 55.0) / 6.8).max(12.0) as usize);
                dl.add_text([row_pos[0] + 40.0, row_pos[1] + 15.0], [0.52f32, 0.62, 0.74, 1.0], &sub_info);

                let data_str = format_bytes(total_bytes);
                let tw = ui.calc_text_size(&data_str)[0];
                dl.add_text([(row_pos[0] + width - tw - 18.0).max(row_pos[0] + 120.0), row_pos[1] + 3.0], [0.75f32, 0.80, 0.88, 1.0], &data_str);

                let ratio = (total_bytes as f32 / max_data).clamp(0.03, 1.0);
                dl.add_rect([row_pos[0] + 30.0, row_pos[1] + 28.0], [row_pos[0] + 30.0 + (width - 44.0).max(10.0) * ratio, row_pos[1] + 30.5], sig_col).filled(true).build();
            }
            ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 2.0]);
        }
    }) {}
}

fn render_usage_hosts_column(filter: &mut SharedFilterState, hosts: &[HostRecord], width: f32, height: f32, ui: &Ui) {
    if let Some(_child) = ui.child_window("usage_col_hosts").size([width, height]).build(|| {
        let selected_app = filter.selected_app.clone();
        let app_filter = selected_app.as_deref();
        let mut filtered: Vec<&HostRecord> = hosts
            .iter()
            .filter(|h| {
                h.matches_app(app_filter)
                    && filter.matches_scope(h.is_local)
                    && filter.selected_country.is_none_or(|cc| h.country_code == cc)
                    && filter.selected_protocol.is_none_or(|p| h.protocols.contains(&p))
            })
            .collect();

        filtered.sort_by_key(|a| a.first_seen_id);

        ui.text_colored([0.96f32, 0.97, 0.99, 1.0], format!("Hosts & IPs ({})", filtered.len()));
        ui.separator();

        let max_val = filtered.iter().map(|h| h.bytes_for_app(app_filter)).max().unwrap_or(1).max(1) as f32;
        let row_h = 38.0;

        for item in filtered.iter().take(80) {
            let row_pos = ui.cursor_screen_pos();
            let bytes = item.bytes_for_app(app_filter);
            let active_socks = item.sockets_for_app(app_filter);

            if ui
                .selectable_config(format!("##host_row_{}", item.first_seen_id))
                .size([width - 12.0, row_h - 3.0])
                .build()
            {
                if let Some(owner_app) = item.stats.primary_app() {
                    let is_same = filter
                        .selected_app
                        .as_deref()
                        .is_some_and(|s| s.eq_ignore_ascii_case(owner_app));
                    filter.selected_app = if is_same {
                        None
                    } else {
                        Some(owner_app.to_string())
                    };
                }
            }
            if ui.is_item_hovered() {
                let apps_list = if item.stats.app_names.is_empty() {
                    String::from("Unknown")
                } else {
                    item.stats.app_names.join(", ")
                };
                ui.tooltip_text(format!(
                    "Host: {}\nEndpoint: {} ({})\nCountry: {} [{}]\nApp(s): {}\nTraffic: {} ({} active sockets)\n\nClick to select application",
                    item.display_title,
                    item.ip_port_str,
                    item.organization,
                    item.country,
                    item.country_code.code(),
                    apps_list,
                    format_bytes(bytes),
                    active_socks
                ));
            }

            let flag_offset = draw_flag_and_code(ui, [row_pos[0] + 4.0, row_pos[1] + 2.0], item.country_code);
            let dl = ui.get_window_draw_list();
            let data_str = format_bytes(bytes);
            let data_w = ui.calc_text_size(&data_str)[0];
            let max_chars = ((width - flag_offset - data_w - 26.0).max(50.0) / 7.0) as usize;
            let host_cut = truncate_str(&item.display_title, max_chars);

            dl.add_text([row_pos[0] + 4.0 + flag_offset, row_pos[1] + 2.0], [0.96f32, 0.97, 0.99, 1.0], &host_cut);
            dl.add_text([(row_pos[0] + width - data_w - 18.0).max(row_pos[0] + 120.0), row_pos[1] + 2.0], [0.75f32, 0.80, 0.88, 1.0], &data_str);

            let owner_prefix = item
                .stats
                .primary_app()
                .map(|a| format!("[{}] ", a))
                .unwrap_or_default();
            let ip_line = format!(
                "{}{} · {} ({} act)",
                owner_prefix, item.ip_port_str, item.organization, active_socks
            );
            let ip_cut = truncate_str(&ip_line, ((width - 24.0) / 6.8).max(16.0) as usize);
            dl.add_text([row_pos[0] + 6.0, row_pos[1] + 17.0], [0.52f32, 0.68, 0.82, 1.0], &ip_cut);

            let ratio = (bytes as f32 / max_val).clamp(0.04, 1.0);
            dl.add_rect([row_pos[0] + 6.0, row_pos[1] + row_h - 4.0], [row_pos[0] + 6.0 + (width - 24.0).max(10.0) * ratio, row_pos[1] + row_h - 2.0], [0.98f32, 0.80, 0.18, 0.90]).filled(true).build();
            ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 2.0]);
        }
    }) {}
}

fn render_usage_protocols_column(filter: &mut SharedFilterState, protocols: &[ProtocolRecord], width: f32, height: f32, ui: &Ui) {
    if let Some(_child) = ui.child_window("usage_col_traffic").size([width, height]).build(|| {
        let app_filter = filter.selected_app.as_deref();
        let mut filtered: Vec<&ProtocolRecord> = protocols
            .iter()
            .filter(|p| p.matches_app(app_filter) && filter.matches_scope(p.is_local))
            .collect();

        filtered.sort_by_key(|a| a.first_seen_id);

        ui.text_colored([0.96f32, 0.97, 0.99, 1.0], format!("Protocols ({})", filtered.len()));
        ui.separator();

        let max_val = filtered.iter().map(|p| p.bytes_for_app(app_filter)).max().unwrap_or(1).max(1) as f32;
        let row_h = 38.0;

        for item in filtered {
            let row_pos = ui.cursor_screen_pos();
            let bytes = item.bytes_for_app(app_filter);
            let is_sel = filter.selected_protocol == Some(item.code);

            if ui.selectable_config(format!("##proto_sel_{}", item.code)).selected(is_sel).size([width - 12.0, row_h - 3.0]).build() {
                filter.selected_protocol = if is_sel { None } else { Some(item.code) };
            }

            let dl = ui.get_window_draw_list();
            let badge = format!("[{}]", item.code);
            let bw = ui.calc_text_size(&badge)[0];
            dl.add_text([row_pos[0] + 6.0, row_pos[1] + 2.0], item.color, &badge);

            let data_str = format_bytes(bytes);
            let dw = ui.calc_text_size(&data_str)[0];
            let desc_cut = truncate_str(item.full_desc, ((width - bw - dw - 28.0).max(40.0) / 7.0) as usize);
            dl.add_text([row_pos[0] + 12.0 + bw, row_pos[1] + 2.0], [0.95f32, 0.96, 0.99, 1.0], &desc_cut);
            dl.add_text([(row_pos[0] + width - dw - 18.0).max(row_pos[0] + 120.0), row_pos[1] + 2.0], [0.75f32, 0.80, 0.88, 1.0], &data_str);
            dl.add_text([row_pos[0] + 6.0, row_pos[1] + 17.0], [0.52f32, 0.62, 0.74, 1.0], format!("{} active sockets", item.sockets_for_app(app_filter)));

            let ratio = (bytes as f32 / max_val).clamp(0.04, 1.0);
            dl.add_rect([row_pos[0] + 6.0, row_pos[1] + row_h - 4.0], [row_pos[0] + 6.0 + (width - 24.0).max(10.0) * ratio, row_pos[1] + row_h - 2.0], item.color).filled(true).build();
            ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 2.0]);
        }
    }) {}
}
