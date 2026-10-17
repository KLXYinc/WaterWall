use imgui::{StyleColor, Ui};

use super::flags::draw_flag_and_code;
use super::groups::{app_signature_color, render_app_group_selector};
use super::icons::IconManager;
use super::widgets::{
    draw_app_icon_or_badge, draw_dual_area_chart, render_shared_filter_bar, truncate_str,
    SharedFilterState, SortMode,
};
use crate::net::{
    classify_ip_location_with_domain, classify_traffic_type, format_bytes,
    terminate_single_socket, terminate_sockets, AppNetworkInfo, ConnectionInfo, CountryCode,
    NetworkMonitor, SocketState, HISTORY_LEN,
};

#[derive(Default)]
pub struct MonitorViewState {
    pub selected_pid: Option<u32>,
    pub open_flow_graph: bool,
    pub last_action_status: Option<String>,
}

pub fn render_firewall_split_view(
    state: &mut MonitorViewState,
    filter: &mut SharedFilterState,
    monitor: &NetworkMonitor,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    ui: &Ui,
) {
    let snapshot = monitor.snapshot();
    render_shared_filter_bar(filter, &snapshot, monitor, ui);

    ui.spacing();
    ui.separator();
    ui.spacing();

    let mut filtered_apps: Vec<&AppNetworkInfo> = snapshot
        .apps
        .iter()
        .filter(|app| filter.matches_app(app))
        .collect();

    match filter.sort_mode {
        SortMode::StableOrder => filtered_apps.sort_by(|a, b| a.first_seen_id.cmp(&b.first_seen_id)),
        SortMode::HighestTraffic => filtered_apps.sort_by(|a, b| {
            let ta = (a.total_downloaded + a.total_uploaded) / (1024 * 64);
            let tb = (b.total_downloaded + b.total_uploaded) / (1024 * 64);
            tb.cmp(&ta).then_with(|| a.first_seen_id.cmp(&b.first_seen_id))
        }),
        SortMode::ActiveSockets => filtered_apps.sort_by(|a, b| {
            b.connections.len().cmp(&a.connections.len()).then_with(|| a.first_seen_id.cmp(&b.first_seen_id))
        }),
        SortMode::Alphabetical => filtered_apps.sort_by(|a, b| {
            a.name.to_lowercase().cmp(&b.name.to_lowercase()).then_with(|| a.first_seen_id.cmp(&b.first_seen_id))
        }),
    }

    if let Some(sel_name) = &filter.selected_app {
        if let Some(found) = filtered_apps.iter().find(|a| a.name.eq_ignore_ascii_case(sel_name)) {
            state.selected_pid = Some(found.pid);
        }
    }

    if state.selected_pid.is_none() || !filtered_apps.iter().any(|a| Some(a.pid) == state.selected_pid) {
        if let Some(first) = filtered_apps.first() {
            state.selected_pid = Some(first.pid);
        }
    }

    let avail = ui.content_region_avail();
    let left_w = (avail[0] * 0.34).clamp(300.0, 410.0);
    let right_w = (avail[0] - left_w - 16.0).max(320.0);
    let view_h = avail[1].max(300.0);

    render_apps_left_panel(state, filter, &filtered_apps, icon_manager, gl, left_w, view_h, ui);
    ui.same_line();

    let selected_app = filtered_apps
        .iter()
        .find(|a| Some(a.pid) == state.selected_pid)
        .copied();
    render_sockets_right_panel(state, filter, selected_app, icon_manager, gl, right_w, view_h, ui);
}

#[allow(clippy::too_many_arguments)]
fn render_apps_left_panel(
    state: &mut MonitorViewState,
    filter: &mut SharedFilterState,
    apps: &[&AppNetworkInfo],
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui
        .child_window("firewall_left_panel")
        .size([width, height])
        .build(|| {
            ui.text_colored([0.96f32, 0.97, 0.99, 1.0], format!("Applications ({})", apps.len()));
            ui.separator();

            let max_data = apps
                .iter()
                .map(|a| a.total_downloaded + a.total_uploaded)
                .max()
                .unwrap_or(1)
                .max(1) as f32;

            for app in apps {
                let is_selected = state.selected_pid == Some(app.pid);
                let sig_col = app_signature_color(&app.name, app.first_seen_id);
                let group = filter.groups.group_for_app(&app.name);
                let row_pos = ui.cursor_screen_pos();
                let row_h = 44.0;

                {
                    let dl = ui.get_window_draw_list();
                    let bg = if is_selected {
                        [0.14f32, 0.48, 0.40, 0.35]
                    } else {
                        [0.11f32, 0.12, 0.15, 0.88]
                    };
                    dl.add_rect(row_pos, [row_pos[0] + width - 10.0, row_pos[1] + row_h], bg)
                        .rounding(5.0)
                        .filled(true)
                        .build();
                    dl.add_rect(row_pos, [row_pos[0] + 5.0, row_pos[1] + row_h], sig_col)
                        .rounding(3.0)
                        .filled(true)
                        .build();
                }

                draw_app_icon_or_badge(
                    ui,
                    icon_manager,
                    gl,
                    app,
                    [row_pos[0] + 12.0, row_pos[1] + 9.0],
                    24.0,
                );

                let text_x = row_pos[0] + 42.0;
                ui.set_cursor_screen_pos([row_pos[0] + 6.0, row_pos[1] + 2.0]);
                if ui
                    .selectable_config(&format!("##fw_sel_{}", app.pid))
                    .selected(is_selected)
                    .size([width - 18.0, row_h - 4.0])
                    .build()
                {
                    state.selected_pid = Some(app.pid);
                    filter.selected_app = Some(app.name.clone());
                }

                let total_bytes = app.total_downloaded + app.total_uploaded;
                let data_str = format_bytes(total_bytes);
                let data_w = ui.calc_text_size(&data_str)[0];
                let name_cut = truncate_str(
                    &app.display_name(),
                    ((width - 58.0 - data_w) / 7.2).max(10.0) as usize,
                );

                {
                    let dl = ui.get_window_draw_list();
                    dl.add_text([text_x, row_pos[1] + 5.0], [0.96f32, 0.97, 0.99, 1.0], &name_cut);
                    dl.add_text(
                        [row_pos[0] + width - data_w - 18.0, row_pos[1] + 5.0],
                        [0.82f32, 0.86, 0.92, 1.0],
                        &data_str,
                    );
                    let grp_sub = truncate_str(
                        &format!("[{}]  ·  {} sockets", group.name, app.connections.len()),
                        ((width - 54.0) / 6.8).max(14.0) as usize,
                    );
                    dl.add_text([text_x, row_pos[1] + 22.0], group.color, &grp_sub);

                    let bar_w = (width - 22.0).max(10.0);
                    let ratio = (total_bytes as f32 / max_data).clamp(0.02, 1.0);
                    dl.add_rect(
                        [row_pos[0] + 8.0, row_pos[1] + row_h - 3.0],
                        [row_pos[0] + 8.0 + bar_w * ratio, row_pos[1] + row_h - 1.0],
                        sig_col,
                    )
                    .filled(true)
                    .build();
                }

                ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 4.0]);
            }
        })
    {}
}

#[allow(clippy::too_many_arguments)]
fn render_sockets_right_panel(
    state: &mut MonitorViewState,
    filter: &mut SharedFilterState,
    selected: Option<&AppNetworkInfo>,
    icon_manager: &mut IconManager,
    gl: &glow::Context,
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui
        .child_window("firewall_right_panel")
        .size([width, height])
        .build(|| {
            let app = match selected {
                Some(a) => a,
                None => {
                    ui.text_disabled("Select an application on the left to assign its Flow Group and inspect sockets.");
                    return;
                }
            };

            let header_pos = ui.cursor_screen_pos();
            draw_app_icon_or_badge(ui, icon_manager, gl, app, header_pos, 36.0);

            ui.set_cursor_screen_pos([header_pos[0] + 46.0, header_pos[1]]);
            ui.text_colored([0.96f32, 0.97, 0.99, 1.0], &app.display_name());
            ui.same_line();
            ui.text_disabled(format!("(PIDs: {:?})", &app.pids[..app.pids.len().min(5)]));

            ui.set_cursor_screen_pos([header_pos[0] + 46.0, header_pos[1] + 18.0]);
            let path_or_cmd = if app.exe_path.is_empty() { &app.cmdline } else { &app.exe_path };
            ui.text_disabled(truncate_str(path_or_cmd, ((width - 60.0) / 7.0).max(20.0) as usize));

            ui.set_cursor_screen_pos([header_pos[0], header_pos[1] + 42.0]);

            render_app_group_selector(
                ui,
                &format!("fw_insp_{}", app.pid),
                &app.name,
                &mut filter.groups,
                &mut filter.new_group_name_buf,
            );
            ui.same_line();
            if ui.button(" [Configure Group Nodes in Flow Graph] ") {
                state.open_flow_graph = true;
            }
            ui.same_line();
            if ui.button(&format!(" [Drop Active Sockets ({})] ", app.connections.len())) {
                let killed = terminate_sockets(&app.connections);
                state.last_action_status = Some(format!(
                    "Terminated {} socket(s) for '{}'",
                    killed.max(app.connections.len()),
                    app.name
                ));
            }

            if let Some(msg) = &state.last_action_status {
                ui.same_line_with_spacing(0.0, 12.0);
                ui.text_colored([0.98f32, 0.82, 0.25, 1.0], msg);
            }

            ui.spacing();
            ui.separator();
            ui.spacing();

            let graph_w = (width - 14.0).max(200.0);
            draw_dual_area_chart(
                ui,
                &format!("##fw_app_wave_{}", app.pid),
                if app.download_history.is_empty() { &[0.0; HISTORY_LEN] } else { &app.download_history },
                if app.upload_history.is_empty() { &[0.0; HISTORY_LEN] } else { &app.upload_history },
                [graph_w, 82.0],
                false,
            );

            ui.spacing();
            ui.text_colored(
                [0.20f32, 0.90, 0.75, 1.0],
                format!("Active Socket Connections ({})", app.connections.len()),
            );
            ui.separator();

            let mut sorted_conns: Vec<&ConnectionInfo> = app.connections.iter().collect();
            sorted_conns.sort_by(|a, b| {
                b.remote_addr
                    .port()
                    .cmp(&a.remote_addr.port())
                    .then_with(|| a.remote_addr.ip().to_string().cmp(&b.remote_addr.ip().to_string()))
                    .then_with(|| a.local_addr.port().cmp(&b.local_addr.port()))
            });

            for (idx, conn) in sorted_conns.into_iter().enumerate() {
                let row_pos = ui.cursor_screen_pos();
                let row_h = 34.0;

                {
                    let dl = ui.get_window_draw_list();
                    dl.add_rect(row_pos, [row_pos[0] + graph_w, row_pos[1] + row_h], [0.11f32, 0.12, 0.16, 0.92])
                        .rounding(4.0)
                        .filled(true)
                        .build();
                }

                let is_remote = conn.remote_addr.port() != 0 && !conn.remote_addr.ip().is_unspecified();
                let loc = if is_remote {
                    classify_ip_location_with_domain(&conn.remote_addr.ip(), conn.domain.as_deref())
                } else {
                    crate::net::IpLocationInfo {
                        country_code: CountryCode::LOCAL,
                        country: "Local Host",
                        organization: "Listening / Local Socket",
                        is_local: true,
                    }
                };

                let (_, proto_code, proto_col) = classify_traffic_type(
                    conn.protocol.as_str(),
                    &conn.local_addr,
                    &conn.remote_addr,
                );

                let flag_w = draw_flag_and_code(ui, [row_pos[0] + 8.0, row_pos[1] + 9.0], loc.country_code);
                ui.set_cursor_screen_pos([row_pos[0] + 10.0 + flag_w, row_pos[1] + 8.0]);
                ui.text_colored(proto_col, format!("[{}]", proto_code));
                ui.same_line();
                ui.text_disabled(format!(":{} ->", conn.local_addr.port()));
                ui.same_line();

                let drop_btn_w = 56.0;
                let state_str = conn.state.as_str();
                let state_w = ui.calc_text_size(state_str)[0];
                let state_x = (row_pos[0] + graph_w - drop_btn_w - state_w - 20.0).max(row_pos[0] + 290.0);
                let avail_endpoint_chars = ((state_x - ui.cursor_screen_pos()[0] - 12.0).max(80.0) / 7.0) as usize;

                if is_remote {
                    if let Some(domain) = &conn.domain {
                        let dom_cut = truncate_str(domain, avail_endpoint_chars.saturating_sub(18).max(12));
                        ui.text_colored([0.35f32, 0.92, 0.65, 1.0], &dom_cut);
                        ui.same_line();
                        let meta_cut = truncate_str(
                            &format!("({}:{} | {})", conn.remote_addr.ip(), conn.remote_addr.port(), loc.organization),
                            avail_endpoint_chars.saturating_sub(dom_cut.len()).max(14),
                        );
                        ui.text_disabled(meta_cut);
                    } else {
                        ui.text_colored([0.94f32, 0.96, 0.99, 1.0], format!("{}:{}", conn.remote_addr.ip(), conn.remote_addr.port()));
                        ui.same_line();
                        ui.text_disabled(truncate_str(&format!("({})", loc.organization), 22));
                    }
                } else {
                    ui.text_disabled(format!("Listening on {}", conn.local_addr));
                }

                ui.set_cursor_screen_pos([state_x, row_pos[1] + 8.0]);
                ui.text_colored(
                    if conn.state == SocketState::Established { [0.25f32, 0.90, 0.55, 1.0] } else { [0.60f32, 0.68, 0.78, 1.0] },
                    state_str,
                );

                ui.set_cursor_screen_pos([row_pos[0] + graph_w - drop_btn_w - 8.0, row_pos[1] + 5.0]);
                let _d_col = ui.push_style_color(StyleColor::Button, [0.55f32, 0.18, 0.20, 0.90]);
                if ui.button_with_size(&format!("Drop##drop_{}_{}", conn.inode, idx), [drop_btn_w, 23.0]) {
                    terminate_single_socket(&conn.remote_addr);
                    state.last_action_status = Some(format!("Dropped socket {}", conn.remote_addr));
                }

                ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 4.0]);
            }
        })
    {}
}
