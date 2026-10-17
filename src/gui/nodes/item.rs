use imgui::node_graph as ng;
use imgui::{StyleColor, Ui};

use super::pin::Pin;
use super::probe::draw_detailed_node_wave;

pub const WIDGET_ROW_H: f32 = 22.0;
pub const TEXT_INPUT_ROW_H: f32 = 23.0;
pub const COMBO_ROW_H: f32 = 23.0;
pub const BUTTON_ROW_H: f32 = 24.0;
pub const CHECKBOX_ROW_H: f32 = 20.0;
pub const READOUT_ROW_H: f32 = 19.0;
pub const METER_ROW_H: f32 = 26.0;
pub const WAVE_ROW_H: f32 = 68.0;
pub const WAVE_SAMPLES: usize = 60;

#[derive(Clone)]
pub enum Item {
    Pin(Pin),
    Readout {
        label: &'static str,
        value: String,
        color: [f32; 4],
    },
    DataMeter {
        speed_text: String,
        volume_text: String,
        fill_ratio: f32,
        color: [f32; 4],
    },
    GroupAppsButton {
        label: String,
        clicked: bool,
    },
    TextInput {
        label: &'static str,
        value: String,
        hint: &'static str,
    },
    Combo {
        label: &'static str,
        options: &'static [&'static str],
        selected: usize,
    },
    Slider {
        label: &'static str,
        min: f32,
        max: f32,
        value: f32,
    },
    Checkbox {
        label: &'static str,
        value: bool,
    },
    WaveGraph {
        values: Box<[f32; WAVE_SAMPLES]>,
        down_values: Box<[f32; WAVE_SAMPLES]>,
        up_values: Box<[f32; WAVE_SAMPLES]>,
        mode: u8,
        color: [f32; 4],
    },
}

impl Item {
    pub fn pin_in(id: i32, name: &'static str) -> Self {
        Item::Pin(Pin::input(id, name))
    }

    pub fn pin_in_colored(id: i32, name: &'static str, color: [f32; 4]) -> Self {
        Item::Pin(Pin::input_colored(id, name, color))
    }

    pub fn pin_out(id: i32, name: &'static str) -> Self {
        Item::Pin(Pin::output(id, name))
    }

    pub fn pin_out_colored(id: i32, name: &'static str, color: [f32; 4]) -> Self {
        Item::Pin(Pin::output_colored(id, name, color))
    }

    pub fn readout(label: &'static str, value: impl Into<String>, color: [f32; 4]) -> Self {
        Item::Readout {
            label,
            value: value.into(),
            color,
        }
    }

    pub fn data_meter(color: [f32; 4]) -> Self {
        Item::DataMeter {
            speed_text: "0 B/s".to_string(),
            volume_text: "0 B".to_string(),
            fill_ratio: 0.05,
            color,
        }
    }

    pub fn group_apps_button() -> Self {
        Item::GroupAppsButton {
            label: "Show / Edit Apps (0)".to_string(),
            clicked: false,
        }
    }

    pub fn action_button(label: impl Into<String>) -> Self {
        Item::GroupAppsButton {
            label: label.into(),
            clicked: false,
        }
    }

    pub fn text_input(label: &'static str, value: impl Into<String>, hint: &'static str) -> Self {
        Item::TextInput {
            label,
            value: value.into(),
            hint,
        }
    }

    pub fn combo(
        label: &'static str,
        options: &'static [&'static str],
        selected: usize,
    ) -> Self {
        Item::Combo {
            label,
            options,
            selected,
        }
    }

    pub fn slider(label: &'static str, min: f32, max: f32, value: f32) -> Self {
        Item::Slider {
            label,
            min,
            max,
            value,
        }
    }

    pub fn checkbox(label: &'static str, value: bool) -> Self {
        Item::Checkbox { label, value }
    }

    pub fn wave(color: [f32; 4]) -> Self {
        Item::WaveGraph {
            values: Box::new([0.0; WAVE_SAMPLES]),
            down_values: Box::new([0.0; WAVE_SAMPLES]),
            up_values: Box::new([0.0; WAVE_SAMPLES]),
            mode: 0,
            color,
        }
    }

    pub fn height(&self) -> f32 {
        match self {
            Item::Pin(_) => ng::row_height(),
            Item::Readout { .. } => READOUT_ROW_H,
            Item::DataMeter { .. } => METER_ROW_H,
            Item::GroupAppsButton { .. } => BUTTON_ROW_H,
            Item::TextInput { .. } => TEXT_INPUT_ROW_H,
            Item::Combo { .. } => COMBO_ROW_H,
            Item::Slider { .. } => WIDGET_ROW_H,
            Item::Checkbox { .. } => CHECKBOX_ROW_H,
            Item::WaveGraph { .. } => WAVE_ROW_H,
        }
    }

    pub fn declare(&mut self, ui: &Ui) {
        match self {
            Item::Pin(pin) => ng::node_pin(ui, pin.id, pin.name, pin.color, pin.is_input),
            Item::Readout {
                label,
                value,
                color,
            } => {
                let row = prepare_row(ui, READOUT_ROW_H);
                ui.text_disabled(*label);
                let vw = ui.calc_text_size(value.as_str())[0];
                let vx = (row[0] + row[2] - vw).max(row[0] + 58.0);
                ui.set_cursor_screen_pos([vx, row[1] + 1.0]);
                ui.text_colored(*color, value.as_str());
            }
            Item::DataMeter {
                speed_text,
                volume_text,
                fill_ratio,
                color,
            } => {
                let row = prepare_row(ui, METER_ROW_H);
                let dl = ui.get_window_draw_list();
                dl.add_text([row[0], row[1]], *color, speed_text.as_str());
                let vw = ui.calc_text_size(volume_text.as_str())[0];
                dl.add_text(
                    [(row[0] + row[2] - vw).max(row[0] + 80.0), row[1]],
                    [0.92f32, 0.95, 1.0, 1.0],
                    volume_text.as_str(),
                );

                let by = row[1] + 16.0;
                let bw = row[2].max(20.0);
                dl.add_rect([row[0], by], [row[0] + bw, by + 6.0], [0.12f32, 0.14, 0.18, 1.0])
                    .rounding(3.0)
                    .filled(true)
                    .build();
                dl.add_rect(
                    [row[0], by],
                    [row[0] + bw * fill_ratio.clamp(0.04, 1.0), by + 6.0],
                    *color,
                )
                .rounding(3.0)
                .filled(true)
                .build();
            }
            Item::GroupAppsButton { label, clicked } => {
                let row = prepare_row(ui, BUTTON_ROW_H);
                let _c = ui.push_style_color(StyleColor::Button, [0.16f32, 0.24, 0.34, 0.95]);
                if ui.button_with_size(format!("{}##grp_apps_btn", label), [row[2], 20.0]) {
                    *clicked = true;
                }
            }
            Item::TextInput { label, value, hint } => {
                let row = prepare_row(ui, TEXT_INPUT_ROW_H);
                let label_w = 56.0;
                ui.text_disabled(*label);
                ui.set_cursor_screen_pos([row[0] + label_w, row[1]]);
                ui.set_next_item_width((row[2] - label_w).max(60.0));
                ui.input_text(format!("##txt_{}", label), value)
                    .hint(*hint)
                    .build();
            }
            Item::Combo {
                label,
                options,
                selected,
            } => {
                let row = prepare_row(ui, COMBO_ROW_H);
                let label_w = 56.0;
                ui.text_disabled(*label);
                ui.set_cursor_screen_pos([row[0] + label_w, row[1]]);
                let btn_w = (row[2] - label_w).max(60.0);
                let cur_opt = options.get(*selected).copied().unwrap_or("Select");
                let popup_id = format!("combo_pop_{}", label);
                if ui.button_with_size(format!("{} [v]##cb_{}", cur_opt, label), [btn_w, 19.0]) {
                    ui.open_popup(&popup_id);
                }
                ui.popup(&popup_id, || {
                    for (idx, &opt) in options.iter().enumerate() {
                        if ui.menu_item(opt) {
                            *selected = idx;
                        }
                    }
                });
            }
            Item::Slider {
                label,
                min,
                max,
                value,
            } => {
                let row = prepare_row(ui, WIDGET_ROW_H);
                ui.set_next_item_width(row[2]);
                ui.slider_config(*label, *min, *max).build(value);
            }
            Item::Checkbox { label, value } => {
                let _row = prepare_row(ui, CHECKBOX_ROW_H);
                ui.checkbox(*label, value);
            }
            Item::WaveGraph {
                values,
                down_values,
                up_values,
                mode,
                color,
            } => {
                let row = prepare_row(ui, WAVE_ROW_H);
                draw_detailed_node_wave(
                    ui,
                    row,
                    values.as_ref(),
                    down_values.as_ref(),
                    up_values.as_ref(),
                    *mode,
                    *color,
                );
            }
        }
    }
}

fn prepare_row(ui: &Ui, height: f32) -> [f32; 4] {
    let row = ng::node_widget_row(height);
    ui.set_cursor_screen_pos([row[0], row[1] + 1.0]);
    row
}
