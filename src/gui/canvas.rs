use imgui::node_graph as ng;
use imgui::{Key, MouseButton, Ui};

use super::app::WaterWallApp;
use super::groups::{render_app_group_selector, render_group_apps_editor_popup};
use crate::gui::nodes::NodeKind;
use crate::gui::theme;

pub fn render_canvas(app: &mut WaterWallApp, gl: &glow::Context, ui: &Ui) {
    let snap = app.monitor.snapshot();

    // Keyboard shortcuts: Ctrl+Z (Undo), Ctrl+Y / Ctrl+Shift+Z (Redo), Ctrl+S (Save)
    if !ui.io().want_text_input && ui.io().key_ctrl {
        if ui.is_key_pressed(Key::Z) {
            if ui.io().key_shift {
                app.status = app.graph.redo();
            } else {
                app.status = app.graph.undo();
            }
        } else if ui.is_key_pressed(Key::Y) {
            app.status = app.graph.redo();
        } else if ui.is_key_pressed(Key::S) {
            app.status = app.graph.save_to_disk(&app.filter.groups);
        }
    }

    if let Some(sel_app) = app.filter.selected_app.clone() {
        ui.text_colored([0.20f32, 0.92, 0.75, 1.0], format!("Selected App: {}", sel_app));
        ui.same_line_with_spacing(0.0, 12.0);
        if let Some(gid) = render_app_group_selector(
            ui,
            "canvas_bar",
            &sel_app,
            &mut app.filter.groups,
            &mut app.filter.new_group_name_buf,
        ) {
            if let Some(grp) = app.filter.groups.get_group(gid) {
                app.graph.push_undo();
                app.graph
                    .push_group_node(gid, &grp.name, grp.color, [35.0, 255.0]);
                app.status = format!("Assigned '{}' to group node '{}'", sel_app, grp.name);
            }
        }
        ui.same_line_with_spacing(0.0, 16.0);
        ui.text_disabled("Drag a node over any rope to insert it  |  Ctrl+Z: Undo  |  Ctrl+S: Save");
        ui.separator();
    }

    let lmb_clicked = ui.is_mouse_clicked(MouseButton::Left);
    let lmb_released = ui.is_mouse_released(MouseButton::Left);
    if lmb_clicked {
        app.graph.track_drag_undo(true, false);
    }

    let avail = ui.content_region_avail();
    let size = [avail[0].max(64.0), avail[1].max(64.0)];
    if ng::begin(ui, "graph", size) {
        app.graph.declare(ui);
    }
    ng::end();

    // Check if the user clicked "Show / Edit Apps (N)" on any AppGroup node
    if let Some(clicked_gid) = app.graph.take_clicked_group_apps() {
        app.editing_group_id = Some(clicked_gid);
        ui.open_popup("canvas_group_apps_editor");
    }

    if let Some(gid) = app.editing_group_id {
        render_group_apps_editor_popup(
            ui,
            "canvas_group_apps_editor",
            gid,
            &mut app.filter.groups,
            &snap.apps,
            &mut app.icon_manager,
            gl,
        );
    }

    while let Some(event) = ng::pop_event() {
        if let ng::Event::RmbCanvas { x, y } = event {
            app.context_click_pos = Some([x as f32, y as f32]);
            ui.open_popup("add_node_popup");
        } else {
            app.status = app.graph.apply(event);
        }
    }

    if lmb_released {
        app.graph.track_drag_undo(false, true);
    }

    ui.popup("add_node_popup", || {
        let pan = ng::pan();
        let spawn_pos = if let Some(pos) = app.context_click_pos.take() {
            [
                (pos[0] - pan[0] - 40.0).max(20.0),
                (pos[1] - pan[1] - 20.0).max(20.0),
            ]
        } else {
            let n = app.graph.node_count() as f32;
            [355.0 + 25.0 * n, 120.0 + 25.0 * n]
        };

        ui.text_colored([0.92f32, 0.95, 1.0, 1.0], "Add Group Policy / Routing Node");
        ui.separator();

        for &kind in &NodeKind::GROUP_RULES {
            let accent = theme::accent_for(kind);
            ui.text_colored(accent, "[+]");
            ui.same_line();
            if ui.menu_item(kind.title()) {
                app.status = app.graph.add_node_at(kind, spawn_pos);
            }
        }

        ui.separator();
        for &kind in &NodeKind::PROBES {
            let accent = theme::accent_for(kind);
            ui.text_colored(accent, "[+]");
            ui.same_line();
            if ui.menu_item(kind.title()) {
                app.status = app.graph.add_node_at(kind, spawn_pos);
            }
        }

        ui.separator();
        ui.menu("Isolate App into New Group Node", || {
            for net_app in snap.apps.iter().take(12) {
                if ui.menu_item(&net_app.display_name()) {
                    app.graph.push_undo();
                    let gid = app
                        .filter
                        .groups
                        .isolate_app_into_own_group(&net_app.name);
                    if let Some(grp) = app.filter.groups.get_group(gid) {
                        app.graph
                            .push_group_node(gid, &grp.name, grp.color, spawn_pos);
                        app.status = format!("Created group node '{}'", grp.name);
                    }
                }
            }
        });
    });
}
