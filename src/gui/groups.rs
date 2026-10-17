use std::collections::HashMap;

use imgui::{StyleColor, Ui};

use super::icons::IconManager;
use super::widgets::{draw_app_icon_or_badge, truncate_str};
use crate::net::{format_bytes, AppNetworkInfo};

/// 12-Color Curated GlassWire Signature Palette for Applications & Groups
pub const GLASSWIRE_PALETTE: [[f32; 4]; 12] = [
    [0.12, 0.92, 0.68, 1.0], // 0: Emerald Mint
    [0.18, 0.78, 0.98, 1.0], // 1: Electric Cyan
    [0.98, 0.38, 0.62, 1.0], // 2: Coral Pink
    [0.99, 0.80, 0.18, 1.0], // 3: Amber Gold
    [0.72, 0.42, 0.98, 1.0], // 4: Violet Purple
    [0.45, 0.92, 0.32, 1.0], // 5: Neon Lime
    [0.98, 0.52, 0.22, 1.0], // 6: Tangerine Orange
    [0.32, 0.58, 0.98, 1.0], // 7: Royal Sky Blue
    [0.94, 0.32, 0.88, 1.0], // 8: Vivid Magenta
    [0.22, 0.94, 0.88, 1.0], // 9: Aqua Turquoise
    [1.00, 0.62, 0.42, 1.0], // 10: Warm Peach
    [0.82, 0.94, 0.24, 1.0], // 11: Chartreuse Yellow
];

/// Returns a deterministic, vibrant GlassWire signature color for an application.
pub fn app_signature_color(app_name: &str, first_seen_id: u64) -> [f32; 4] {
    if first_seen_id > 0 {
        return GLASSWIRE_PALETTE
            [((first_seen_id as usize).wrapping_sub(1)) % GLASSWIRE_PALETTE.len()];
    }
    let mut hash = 5381usize;
    for b in app_name.bytes() {
        hash = ((hash << 5).wrapping_add(hash)) ^ (b.to_ascii_lowercase() as usize);
    }
    GLASSWIRE_PALETTE[hash % GLASSWIRE_PALETTE.len()]
}

/// Represents a named Application Group that becomes a dedicated Node in the Flow Graph.
/// Group 0 is always "All Apps (Default)".
#[derive(Clone, Debug)]
pub struct AppGroup {
    pub id: usize,
    pub name: String,
    pub color: [f32; 4],
}

/// Manages App Groups ("All Apps (Default)" + custom/category groups) and app -> group assignments.
pub struct AppGroupManager {
    pub groups: Vec<AppGroup>,
    pub app_to_group: HashMap<String, usize>, // lowercase app_name -> group_id
    next_group_id: usize,
}

impl Default for AppGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AppGroupManager {
    pub fn new() -> Self {
        let groups = vec![
            AppGroup {
                id: 0,
                name: "All Apps (Default)".to_string(),
                color: [0.15, 0.88, 0.65, 1.0],
            },
            AppGroup {
                id: 1,
                name: "Web & Browsers".to_string(),
                color: [0.18, 0.78, 0.98, 1.0],
            },
            AppGroup {
                id: 2,
                name: "Chat & Social".to_string(),
                color: [0.98, 0.38, 0.62, 1.0],
            },
            AppGroup {
                id: 3,
                name: "Dev & Services".to_string(),
                color: [0.99, 0.80, 0.18, 1.0],
            },
            AppGroup {
                id: 4,
                name: "Gaming & Media".to_string(),
                color: [0.72, 0.42, 0.98, 1.0],
            },
        ];
        Self {
            groups,
            app_to_group: HashMap::new(),
            next_group_id: 5,
        }
    }

    pub fn group_for_app(&self, app_name: &str) -> &AppGroup {
        let gid = self.group_id_for_app(app_name);
        self.groups
            .iter()
            .find(|g| g.id == gid)
            .unwrap_or(&self.groups[0])
    }

    pub fn group_id_for_app(&self, app_name: &str) -> usize {
        self.app_to_group
            .get(&app_name.to_lowercase())
            .copied()
            .unwrap_or(0)
    }

    pub fn get_group(&self, group_id: usize) -> Option<&AppGroup> {
        self.groups.iter().find(|g| g.id == group_id)
    }

    pub fn assign_app(&mut self, app_name: &str, group_id: usize) {
        let key = app_name.to_lowercase();
        if group_id == 0 {
            self.app_to_group.remove(&key);
        } else {
            self.app_to_group.insert(key, group_id);
        }
    }

    pub fn isolate_app_into_own_group(&mut self, app_name: &str) -> usize {
        let group_title = format!("Group: {}", app_name);
        if let Some(existing) = self
            .groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(&group_title))
        {
            let gid = existing.id;
            self.assign_app(app_name, gid);
            return gid;
        }
        let gid = self.next_group_id;
        self.next_group_id += 1;
        let color = GLASSWIRE_PALETTE[gid % GLASSWIRE_PALETTE.len()];
        self.groups.push(AppGroup {
            id: gid,
            name: group_title,
            color,
        });
        self.assign_app(app_name, gid);
        gid
    }

    pub fn create_custom_group(&mut self, name: &str) -> usize {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return 0;
        }
        if let Some(existing) = self
            .groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(trimmed))
        {
            return existing.id;
        }
        let gid = self.next_group_id;
        self.next_group_id += 1;
        let color = GLASSWIRE_PALETTE[gid % GLASSWIRE_PALETTE.len()];
        self.groups.push(AppGroup {
            id: gid,
            name: trimmed.to_string(),
            color,
        });
        gid
    }

    pub fn apps_in_group<'a>(
        &self,
        group_id: usize,
        apps: &'a [AppNetworkInfo],
    ) -> Vec<&'a AppNetworkInfo> {
        apps.iter()
            .filter(|a| self.group_id_for_app(&a.name) == group_id)
            .collect()
    }

    /// Returns Group 0 ("All Apps (Default)") plus any group with assigned apps.
    pub fn active_group_ids(&self) -> Vec<usize> {
        let mut ids = vec![0usize];
        for &gid in self.app_to_group.values() {
            if gid != 0 && !ids.contains(&gid) {
                ids.push(gid);
            }
        }
        ids.sort_unstable();
        ids
    }
}

/// Renders the Group Assignment selector for the currently selected application.
pub fn render_app_group_selector(
    ui: &Ui,
    id_suffix: &str,
    app_name: &str,
    groups: &mut AppGroupManager,
    new_group_buf: &mut String,
) -> Option<usize> {
    let cur_group = groups.group_for_app(app_name).clone();
    let popup_id = format!("grp_popup_{}", id_suffix);

    let _btn_col = ui.push_style_color(
        StyleColor::Button,
        [
            cur_group.color[0] * 0.28,
            cur_group.color[1] * 0.28,
            cur_group.color[2] * 0.32,
            0.95,
        ],
    );
    let _txt_col = ui.push_style_color(StyleColor::Text, cur_group.color);
    if ui.button(&format!(" Flow Group: {} [v]##gbtn_{} ", cur_group.name, id_suffix)) {
        ui.open_popup(&popup_id);
    }
    drop(_txt_col);
    drop(_btn_col);

    let mut changed_to = None;
    ui.popup(&popup_id, || {
        ui.text_colored(
            [0.95f32, 0.97, 1.0, 1.0],
            format!("Move '{}' to Flow Graph Group:", app_name),
        );
        ui.separator();

        let all_groups = groups.groups.clone();
        for g in &all_groups {
            let is_cur = g.id == cur_group.id;
            ui.text_colored(g.color, if is_cur { "[*]" } else { "[ ]" });
            ui.same_line();
            if ui.menu_item(&format!("{}##gitem_{}_{}", g.name, g.id, id_suffix)) {
                groups.assign_app(app_name, g.id);
                changed_to = Some(g.id);
            }
        }

        ui.separator();
        if ui.menu_item(&format!(
            "+ Isolate '{}' as Separate Group Node##iso_{}",
            app_name, id_suffix
        )) {
            let new_id = groups.isolate_app_into_own_group(app_name);
            changed_to = Some(new_id);
        }

        ui.separator();
        ui.text_disabled("New Group Node:");
        ui.set_next_item_width(145.0);
        ui.input_text(&format!("##new_grp_{}", id_suffix), new_group_buf)
            .hint("Group name...")
            .build();
        ui.same_line();
        if ui.button(&format!("Create##mk_grp_{}", id_suffix)) && !new_group_buf.trim().is_empty()
        {
            let gid = groups.create_custom_group(new_group_buf);
            groups.assign_app(app_name, gid);
            new_group_buf.clear();
            changed_to = Some(gid);
            ui.close_current_popup();
        }
    });

    changed_to
}

/// Renders the interactive "Show / Edit Apps in Group" popup with real Linux app icons & names
/// so the user can view, remove, or add applications to `group_id`.
pub fn render_group_apps_editor_popup(
    ui: &Ui,
    popup_id: &str,
    group_id: usize,
    groups: &mut AppGroupManager,
    apps: &[AppNetworkInfo],
    icon_manager: &mut IconManager,
    gl: &glow::Context,
) {
    ui.popup(popup_id, || {
        let group = groups
            .get_group(group_id)
            .cloned()
            .unwrap_or_else(|| groups.groups[0].clone());

        ui.text_colored(group.color, format!("Group Apps — {}", group.name));
        ui.separator();

        let members: Vec<&AppNetworkInfo> = apps
            .iter()
            .filter(|a| groups.group_id_for_app(&a.name) == group_id)
            .collect();
        let others: Vec<&AppNetworkInfo> = apps
            .iter()
            .filter(|a| groups.group_id_for_app(&a.name) != group_id)
            .collect();

        ui.text_colored(
            [0.88f32, 0.92, 0.98, 1.0],
            format!("Apps in this Group ({}):", members.len()),
        );

        let list_w = 340.0;
        if let Some(_c) = ui
            .child_window(&format!("grp_members_{}", group_id))
            .size([list_w, 150.0])
            .build(|| {
                if members.is_empty() {
                    ui.text_disabled("No apps currently in this group.");
                }
                for app in &members {
                    let row_pos = ui.cursor_screen_pos();
                    let row_h = 26.0;
                    draw_app_icon_or_badge(
                        ui,
                        icon_manager,
                        gl,
                        app,
                        [row_pos[0] + 2.0, row_pos[1] + 2.0],
                        18.0,
                    );
                    ui.set_cursor_screen_pos([row_pos[0] + 26.0, row_pos[1] + 3.0]);
                    ui.text(truncate_str(&app.display_name(), 22));

                    let bytes_str = format_bytes(app.total_downloaded + app.total_uploaded);
                    ui.same_line_with_spacing(0.0, 8.0);
                    ui.text_disabled(&bytes_str);

                    if group_id != 0 {
                        ui.set_cursor_screen_pos([row_pos[0] + list_w - 76.0, row_pos[1] + 1.0]);
                        let _c = ui.push_style_color(StyleColor::Button, [0.55f32, 0.18, 0.22, 0.90]);
                        if ui.button_with_size(&format!("Remove##rm_{}", app.pid), [64.0, 21.0]) {
                            groups.assign_app(&app.name, 0);
                        }
                    } else {
                        ui.set_cursor_screen_pos([row_pos[0] + list_w - 86.0, row_pos[1] + 1.0]);
                        if ui.button_with_size(&format!("Isolate##iso_m_{}", app.pid), [74.0, 21.0]) {
                            groups.isolate_app_into_own_group(&app.name);
                        }
                    }
                    ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h]);
                }
            })
        {}

        if !others.is_empty() {
            ui.separator();
            ui.text_colored(
                [0.25f32, 0.92, 0.72, 1.0],
                format!("+ Add Apps to '{}' ({}):", group.name, others.len()),
            );
            if let Some(_c) = ui
                .child_window(&format!("grp_others_{}", group_id))
                .size([list_w, 150.0])
                .build(|| {
                    for app in &others {
                        let row_pos = ui.cursor_screen_pos();
                        let row_h = 26.0;
                        draw_app_icon_or_badge(
                            ui,
                            icon_manager,
                            gl,
                            app,
                            [row_pos[0] + 2.0, row_pos[1] + 2.0],
                            18.0,
                        );
                        ui.set_cursor_screen_pos([row_pos[0] + 26.0, row_pos[1] + 3.0]);
                        let cur_g = groups.group_for_app(&app.name);
                        ui.text(truncate_str(&app.display_name(), 18));
                        ui.same_line();
                        ui.text_disabled(format!("[{}]", truncate_str(&cur_g.name, 10)));

                        ui.set_cursor_screen_pos([row_pos[0] + list_w - 68.0, row_pos[1] + 1.0]);
                        let _c = ui.push_style_color(StyleColor::Button, [0.15f32, 0.52, 0.38, 0.95]);
                        if ui.button_with_size(&format!("+ Add##add_{}", app.pid), [56.0, 21.0]) {
                            groups.assign_app(&app.name, group_id);
                        }
                        ui.set_cursor_screen_pos([row_pos[0], row_pos[1] + row_h]);
                    }
                })
            {}
        }
    });
}
