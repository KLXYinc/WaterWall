use imgui::{Key, StyleColor, Ui};

use super::app::{ViewMode, WaterWallApp};
use crate::net::{format_bytes, format_speed, NetworkSnapshot};
use crate::utils::is_elevated;

pub fn render_toolbar(app: &mut WaterWallApp, snap: &NetworkSnapshot, ui: &Ui) {
    let active_color = [0.15f32, 0.50, 0.85, 1.0];

    // Keyboard shortcuts 1..=5 when no text input is active
    if !ui.io().want_text_input && !ui.io().key_ctrl {
        if ui.is_key_pressed(Key::Alpha1) {
            app.view_mode = ViewMode::Usage;
        } else if ui.is_key_pressed(Key::Alpha2) {
            app.view_mode = ViewMode::TrafficMonitor;
        } else if ui.is_key_pressed(Key::Alpha3) {
            app.view_mode = ViewMode::Firewall;
        } else if ui.is_key_pressed(Key::Alpha4) {
            app.view_mode = ViewMode::FlowGraph;
        } else if ui.is_key_pressed(Key::Alpha5) {
            app.view_mode = ViewMode::DnsAndAlerts;
        }
    }

    ui.text_colored([0.96f32, 0.97, 0.99, 1.0], "WaterWall");
    ui.same_line();
    if is_elevated() {
        ui.text_colored([0.20f32, 0.92, 0.72, 1.0], "[ROOT · System+User]");
    } else {
        ui.text_colored([0.98f32, 0.76, 0.22, 1.0], "[User Apps Only]");
    }
    ui.same_line_with_spacing(0.0, 10.0);

    let unsaved = app.graph.has_unsaved_changes(&app.filter.groups);
    let flow_label = if unsaved {
        " [4] Flow Graph (Ropes) * "
    } else {
        " [4] Flow Graph (Ropes) "
    };
    let alerts_label = format!(
        " [5] DNS ({}) & Alerts ({}) ",
        snap.dns_events.len(),
        snap.alerts.len()
    );

    for (mode, label) in [
        (ViewMode::Usage, " [1] Network Usage "),
        (ViewMode::TrafficMonitor, " [2] Traffic Monitor "),
        (ViewMode::Firewall, " [3] App Connections "),
        (ViewMode::FlowGraph, flow_label),
        (ViewMode::DnsAndAlerts, alerts_label.as_str()),
    ] {
        let is_active = app.view_mode == mode;
        let _style = is_active.then(|| ui.push_style_color(StyleColor::Button, active_color));
        if ui.button(label) {
            app.view_mode = mode;
        }
        ui.same_line();
    }

    ui.same_line_with_spacing(0.0, 8.0);
    ui.text_disabled("|");
    ui.same_line_with_spacing(0.0, 8.0);

    if app.view_mode == ViewMode::FlowGraph {
        if ui.button(" + Add ") {
            ui.open_popup("add_node_popup");
        }
        if !is_elevated() && !std::path::Path::new("/sys/fs/bpf/waterwall_slots").exists() {
            ui.same_line();
            let _c = ui.push_style_color(StyleColor::Button, [0.75f32, 0.42, 0.12, 0.95]);
            if ui.button("Enable eBPF Root Hook") {
                app.status = crate::net::request_ebpf_elevation();
            }
        }
        ui.same_line();
        let undo_lbl = format!("Undo ({})", app.graph.undo_count());
        if ui.button(&undo_lbl) {
            app.status = app.graph.undo();
        }
        if app.graph.can_redo() {
            ui.same_line();
            if ui.button("Redo") {
                app.status = app.graph.redo();
            }
        }
        ui.same_line();
        render_save_button(app, unsaved, ui);
        ui.same_line();
        if ui.button("Reset") {
            app.status = app.graph.reset_with_undo();
        }
        ui.same_line();
        if ui.button("Layout") {
            app.status = app.graph.auto_layout();
        }
        ui.same_line_with_spacing(0.0, 8.0);
        if unsaved {
            ui.text_colored(
                [0.98f32, 0.72, 0.22, 1.0],
                format!("UNSAVED CHANGES (Click Save to apply)  |  {}", app.status),
            );
        } else {
            ui.text_disabled(&app.status);
        }
    } else {
        if unsaved {
            render_save_button(app, true, ui);
            ui.same_line_with_spacing(0.0, 10.0);
        }
        ui.text_colored(
            [0.15f32, 0.90, 0.78, 1.0],
            format!(
                "IN: {} ({})",
                format_speed(snap.system_download_speed),
                format_bytes(snap.session_total_download)
            ),
        );
        ui.same_line_with_spacing(0.0, 12.0);
        ui.text_colored(
            [0.98f32, 0.45, 0.65, 1.0],
            format!(
                "OUT: {} ({})",
                format_speed(snap.system_upload_speed),
                format_bytes(snap.session_total_upload)
            ),
        );
    }

    let avail_w = ui.content_region_avail()[0];
    if avail_w > 64.0 {
        ui.same_line_with_spacing(0.0, avail_w - 58.0);
    } else {
        ui.same_line();
    }
    if ui.button(" Quit ") {
        app.should_exit = true;
    }

    ui.separator();
}

fn render_save_button(app: &mut WaterWallApp, unsaved: bool, ui: &Ui) {
    let (btn_col, hov_col, label) = if unsaved {
        (
            [0.94f32, 0.52, 0.08, 1.0],
            [1.00f32, 0.64, 0.16, 1.0],
            " * Save (Unsaved) ",
        )
    } else {
        (
            [0.14f32, 0.48, 0.34, 0.92],
            [0.18f32, 0.58, 0.42, 1.0],
            " Saved ",
        )
    };
    let _b = ui.push_style_color(StyleColor::Button, btn_col);
    let _h = ui.push_style_color(StyleColor::ButtonHovered, hov_col);
    if ui.button(label) {
        app.status = app.graph.save_to_disk(&app.filter.groups);
    }
    if ui.is_item_hovered() {
        if unsaved {
            ui.tooltip_text("Unsaved network changes! Click (or press Ctrl+S) to save and apply rope/node rules.");
        } else {
            ui.tooltip_text("All Flow Graph & Group rules are saved and active.");
        }
    }
}
