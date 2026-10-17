use imgui::Ui;

use super::flags::draw_flag_and_code;
use super::groups::render_app_group_selector;
use super::widgets::{render_shared_filter_bar, truncate_str, SharedFilterState};
use crate::net::{
    classify_ip_location_with_domain, format_bytes, DnsEvent, NetworkMonitor, SecurityAlert,
};

#[derive(Default)]
pub struct AlertsViewState {
    pub open_flow_graph: bool,
}

pub fn render_dns_and_alerts_view(
    state: &mut AlertsViewState,
    filter: &mut SharedFilterState,
    monitor: &NetworkMonitor,
    ui: &Ui,
) {
    let snap = monitor.snapshot();
    render_shared_filter_bar(filter, &snap, monitor, ui);

    ui.spacing();
    ui.separator();
    ui.spacing();

    // Top Status Banner: Detected Linux VPN / Tunnel Interfaces + Selected App Group Assignment
    if snap.vpn_interfaces.is_empty() {
        ui.text_disabled("System VPN / Tunnel Interfaces: None detected (Configure VPN/Proxy Nodes in Flow Graph)");
    } else {
        ui.text_colored([0.18f32, 0.92, 0.72, 1.0], "Active Linux VPN / Tunnel Interfaces:");
        for v in &snap.vpn_interfaces {
            ui.same_line_with_spacing(0.0, 12.0);
            let col = if v.is_up {
                [0.20f32, 0.92, 0.68, 1.0]
            } else {
                [0.65f32, 0.70, 0.78, 1.0]
            };
            ui.text_colored(
                col,
                format!(
                    "[{} · {} · RX {} / TX {}]",
                    v.name,
                    v.kind,
                    format_bytes(v.rx_bytes),
                    format_bytes(v.tx_bytes)
                ),
            );
        }
    }

    if let Some(sel_app) = filter.selected_app.clone() {
        ui.same_line_with_spacing(0.0, 20.0);
        render_app_group_selector(
            ui,
            "alerts_bar",
            &sel_app,
            &mut filter.groups,
            &mut filter.new_group_name_buf,
        );
        ui.same_line();
        if ui.button(" [Open Flow Graph] ") {
            state.open_flow_graph = true;
        }
    }

    ui.spacing();
    ui.separator();
    ui.spacing();

    let avail = ui.content_region_avail();
    let col_w = ((avail[0] - 16.0) * 0.5).max(320.0);
    let col_h = avail[1].max(240.0);

    // LEFT PANEL: Live DNS Query & Hostname Resolution Tracker
    render_dns_tracker_panel(filter, &snap.dns_events, col_w, col_h, ui);
    ui.same_line();

    // RIGHT PANEL: GlassWire Security & First-Network-Activity Alerts
    render_security_alerts_panel(filter, &snap.alerts, col_w, col_h, ui);
}

fn render_dns_tracker_panel(
    filter: &mut SharedFilterState,
    dns_events: &[DnsEvent],
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui
        .child_window("dns_tracker_panel")
        .size([width, height])
        .build(|| {
            let filtered: Vec<&DnsEvent> = dns_events
                .iter()
                .filter(|e| {
                    if let Some(sel) = &filter.selected_app {
                        if !e.app_name.eq_ignore_ascii_case(sel) {
                            return false;
                        }
                    }
                    if !filter.search_query.is_empty() {
                        let q = filter.search_query.to_lowercase();
                        if !e.domain.to_lowercase().contains(&q)
                            && !e.ip.to_string().contains(&q)
                            && !e.app_name.to_lowercase().contains(&q)
                        {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            ui.text_colored(
                [0.20f32, 0.86, 0.98, 1.0],
                format!("Live DNS Resolution & Query Log ({})", filtered.len()),
            );
            ui.separator();

            if filtered.is_empty() {
                ui.dummy([0.0, 16.0]);
                ui.text_disabled("No DNS events matching current filter.");
                return;
            }

            let row_h = 38.0;
            for ev in filtered.into_iter().take(120) {
                let row_pos = ui.cursor_screen_pos();
                let loc = classify_ip_location_with_domain(&ev.ip, Some(&ev.domain));

                {
                    let dl = ui.get_window_draw_list();
                    dl.add_rect(
                        row_pos,
                        [row_pos[0] + width - 10.0, row_pos[1] + row_h],
                        [0.10f32, 0.12, 0.16, 0.90],
                    )
                    .rounding(4.0)
                    .filled(true)
                    .build();
                }

                if ui
                    .selectable_config(&format!("##dns_ev_{}", ev.id))
                    .size([width - 12.0, row_h - 2.0])
                    .build()
                {
                    filter.selected_app = Some(ev.app_name.clone());
                }

                let flag_w = draw_flag_and_code(
                    ui,
                    [row_pos[0] + 6.0, row_pos[1] + 4.0],
                    loc.country_code,
                );

                let dl = ui.get_window_draw_list();
                let dom_cut = truncate_str(&ev.domain, ((width - flag_w - 135.0) / 7.0).max(12.0) as usize);
                dl.add_text(
                    [row_pos[0] + 8.0 + flag_w, row_pos[1] + 3.0],
                    [0.95f32, 0.97, 1.0, 1.0],
                    &dom_cut,
                );

                let right_meta = format!("[{}] {:.1}ms", ev.protocol, ev.latency_ms);
                let rw = ui.calc_text_size(&right_meta)[0];
                dl.add_text(
                    [(row_pos[0] + width - rw - 16.0).max(row_pos[0] + 180.0), row_pos[1] + 3.0],
                    [0.35f32, 0.88, 0.75, 1.0],
                    &right_meta,
                );

                let sub = format!(
                    "IP: {}  ·  App: {}  ·  {}s ago",
                    ev.ip, ev.app_name, ev.age_secs
                );
                let sub_cut = truncate_str(&sub, ((width - 24.0) / 6.8).max(18.0) as usize);
                dl.add_text(
                    [row_pos[0] + 8.0, row_pos[1] + 20.0],
                    [0.56f32, 0.68, 0.82, 1.0],
                    &sub_cut,
                );

                ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 4.0]);
            }
        })
    {}
}

fn render_security_alerts_panel(
    filter: &mut SharedFilterState,
    alerts: &[SecurityAlert],
    width: f32,
    height: f32,
    ui: &Ui,
) {
    if let Some(_child) = ui
        .child_window("security_alerts_panel")
        .size([width, height])
        .build(|| {
            ui.text_colored(
                [0.98f32, 0.78, 0.22, 1.0],
                format!("GlassWire Security & First-Activity Alerts ({})", alerts.len()),
            );
            ui.separator();

            if alerts.is_empty() {
                ui.dummy([0.0, 16.0]);
                ui.text_disabled("No security alerts recorded in this session.");
                return;
            }

            let row_h = 40.0;
            for alert in alerts.iter().take(120) {
                let row_pos = ui.cursor_screen_pos();
                let (badge_txt, badge_col) = alert.kind.badge();

                {
                    let dl = ui.get_window_draw_list();
                    dl.add_rect(
                        row_pos,
                        [row_pos[0] + width - 10.0, row_pos[1] + row_h],
                        [0.11f32, 0.12, 0.15, 0.92],
                    )
                    .rounding(4.0)
                    .filled(true)
                    .build();
                    dl.add_rect(
                        row_pos,
                        [row_pos[0] + 4.0, row_pos[1] + row_h],
                        badge_col,
                    )
                    .rounding(2.0)
                    .filled(true)
                    .build();
                }

                if ui
                    .selectable_config(&format!("##sec_alert_{}", alert.id))
                    .size([width - 12.0, row_h - 2.0])
                    .build()
                {
                    filter.selected_app = Some(alert.app_name.clone());
                }

                let mut x_cur = row_pos[0] + 10.0;
                if let Some(cc) = alert.country {
                    x_cur += draw_flag_and_code(ui, [x_cur, row_pos[1] + 4.0], cc);
                }

                let dl = ui.get_window_draw_list();
                let b_str = format!("[{}]", badge_txt);
                let bw = ui.calc_text_size(&b_str)[0];
                dl.add_text([x_cur, row_pos[1] + 3.0], badge_col, &b_str);
                dl.add_text(
                    [x_cur + bw + 8.0, row_pos[1] + 3.0],
                    [0.96f32, 0.97, 1.0, 1.0],
                    &alert.app_name,
                );

                let age_str = format!("{}s ago", alert.age_secs);
                let aw = ui.calc_text_size(&age_str)[0];
                dl.add_text(
                    [row_pos[0] + width - aw - 18.0, row_pos[1] + 3.0],
                    [0.55f32, 0.62, 0.72, 1.0],
                    &age_str,
                );

                let detail_cut = truncate_str(&alert.detail, ((width - 26.0) / 6.8).max(18.0) as usize);
                dl.add_text(
                    [row_pos[0] + 10.0, row_pos[1] + 21.0],
                    [0.65f32, 0.75, 0.86, 1.0],
                    &detail_cut,
                );

                ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h + 4.0]);
            }
        })
    {}
}
