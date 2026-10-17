use imgui::Ui;

use super::flag_catalog::{flag_spec_for, FlagSpec};
use crate::net::CountryCode;

pub const FLAG_W: f32 = 20.0;
pub const FLAG_H: f32 = 14.0;

/// Draws a crisp 20x14 graphical country flag at `pos` for ANY ISO 3166-1 country on Earth.
pub fn draw_country_flag(ui: &Ui, pos: [f32; 2], country: CountryCode) {
    let x = pos[0];
    let y = pos[1];
    let w = FLAG_W;
    let h = FLAG_H;
    let x2 = x + w;
    let y2 = y + h;
    let white = [0.96f32, 0.97, 0.99, 1.0];

    let dl = ui.get_window_draw_list();

    match flag_spec_for(country) {
        FlagSpec::H2(c1, c2) => {
            dl.add_rect([x, y], [x2, y + h * 0.5], c1).filled(true).build();
            dl.add_rect([x, y + h * 0.5], [x2, y2], c2).filled(true).build();
        }
        FlagSpec::H3(c1, c2, c3) => {
            let h3 = h / 3.0;
            dl.add_rect([x, y], [x2, y + h3], c1).filled(true).build();
            dl.add_rect([x, y + h3], [x2, y + h3 * 2.0], c2).filled(true).build();
            dl.add_rect([x, y + h3 * 2.0], [x2, y2], c3).filled(true).build();
        }
        FlagSpec::V2(c1, c2) => {
            dl.add_rect([x, y], [x + w * 0.45, y2], c1).filled(true).build();
            dl.add_rect([x + w * 0.45, y], [x2, y2], c2).filled(true).build();
        }
        FlagSpec::V3(c1, c2, c3) => {
            let w3 = w / 3.0;
            dl.add_rect([x, y], [x + w3, y2], c1).filled(true).build();
            dl.add_rect([x + w3, y], [x + w3 * 2.0, y2], c2).filled(true).build();
            dl.add_rect([x + w3 * 2.0, y], [x2, y2], c3).filled(true).build();
        }
        FlagSpec::BandH(edge, mid, edge2) => {
            dl.add_rect([x, y], [x2, y2], edge).filled(true).build();
            dl.add_rect([x, y + h * 0.65], [x2, y2], edge2).filled(true).build();
            dl.add_rect([x, y + h * 0.25], [x2, y + h * 0.75], mid)
                .filled(true)
                .build();
        }
        FlagSpec::Nordic(bg, cross, inner) => {
            dl.add_rect([x, y], [x2, y2], bg).filled(true).build();
            let cx = x + w * 0.35;
            let cy = y + h * 0.5;
            dl.add_rect([cx - 1.7, y], [cx + 1.7, y2], cross).filled(true).build();
            dl.add_rect([x, cy - 1.7], [x2, cy + 1.7], cross).filled(true).build();
            if let Some(in_col) = inner {
                dl.add_rect([cx - 0.8, y], [cx + 0.8, y2], in_col).filled(true).build();
                dl.add_rect([x, cy - 0.8], [x2, cy + 0.8], in_col).filled(true).build();
            }
        }
        FlagSpec::CenterCross(bg, cross) => {
            dl.add_rect([x, y], [x2, y2], bg).filled(true).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_rect([cx - 1.6, y], [cx + 1.6, y2], cross).filled(true).build();
            dl.add_rect([x, cy - 1.6], [x2, cy + 1.6], cross).filled(true).build();
        }
        FlagSpec::Saltire(bg, cross) => {
            dl.add_rect([x, y], [x2, y2], bg).filled(true).build();
            dl.add_line([x + 1.0, y + 1.0], [x2 - 1.0, y2 - 1.0], cross)
                .thickness(2.2)
                .build();
            dl.add_line([x + 1.0, y2 - 1.0], [x2 - 1.0, y + 1.0], cross)
                .thickness(2.2)
                .build();
        }
        FlagSpec::Disc(bg, disc) => {
            dl.add_rect([x, y], [x2, y2], bg).filled(true).build();
            dl.add_circle([x + w * 0.5, y + h * 0.5], 3.4, disc)
                .filled(true)
                .build();
        }
        FlagSpec::TriH2(c1, c2, tri) => {
            dl.add_rect([x, y], [x2, y + h * 0.5], c1).filled(true).build();
            dl.add_rect([x, y + h * 0.5], [x2, y2], c2).filled(true).build();
            dl.add_triangle([x, y], [x + w * 0.48, y + h * 0.5], [x, y2], tri)
                .filled(true)
                .build();
        }
        FlagSpec::TriH3(c1, c2, c3, tri) => {
            let h3 = h / 3.0;
            dl.add_rect([x, y], [x2, y + h3], c1).filled(true).build();
            dl.add_rect([x, y + h3], [x2, y + h3 * 2.0], c2).filled(true).build();
            dl.add_rect([x, y + h3 * 2.0], [x2, y2], c3).filled(true).build();
            dl.add_triangle([x, y], [x + w * 0.46, y + h * 0.5], [x, y2], tri)
                .filled(true)
                .build();
        }
        FlagSpec::Canton(s1, s2, canton) => {
            dl.add_rect([x, y], [x2, y + h * 0.5], s1).filled(true).build();
            dl.add_rect([x, y + h * 0.5], [x2, y2], s2).filled(true).build();
            dl.add_rect([x, y], [x + w * 0.46, y + h * 0.54], canton)
                .filled(true)
                .build();
            dl.add_circle([x + w * 0.23, y + h * 0.27], 1.3, white)
                .filled(true)
                .build();
        }
        FlagSpec::US => {
            dl.add_rect([x, y], [x2, y2], white).filled(true).build();
            let sh = h / 7.0;
            for i in (0..7).step_by(2) {
                let sy = y + i as f32 * sh;
                dl.add_rect([x, sy], [x2, sy + sh], [0.76, 0.12, 0.20, 1.0])
                    .filled(true)
                    .build();
            }
            dl.add_rect([x, y], [x + w * 0.48, y + h * 0.55], [0.06, 0.18, 0.46, 1.0])
                .filled(true)
                .build();
            for r in 0..2 {
                for c in 0..3 {
                    dl.add_circle([x + 2.2 + c as f32 * 2.8, y + 2.2 + r as f32 * 3.2], 0.65, white)
                        .filled(true)
                        .build();
                }
            }
        }
        FlagSpec::GB => {
            dl.add_rect([x, y], [x2, y2], [0.04, 0.15, 0.44, 1.0]).filled(true).build();
            dl.add_line([x + 1.0, y + 1.0], [x2 - 1.0, y2 - 1.0], white).thickness(2.0).build();
            dl.add_line([x + 1.0, y2 - 1.0], [x2 - 1.0, y + 1.0], white).thickness(2.0).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_rect([cx - 2.2, y], [cx + 2.2, y2], white).filled(true).build();
            dl.add_rect([x, cy - 2.2], [x2, cy + 2.2], white).filled(true).build();
            dl.add_rect([cx - 1.2, y], [cx + 1.2, y2], [0.82, 0.10, 0.18, 1.0]).filled(true).build();
            dl.add_rect([x, cy - 1.2], [x2, cy + 1.2], [0.82, 0.10, 0.18, 1.0]).filled(true).build();
        }
        FlagSpec::CH => {
            dl.add_rect([x, y], [x2, y2], [0.86, 0.10, 0.15, 1.0]).filled(true).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_rect([cx - 1.5, y + 2.5], [cx + 1.5, y2 - 2.5], white).filled(true).build();
            dl.add_rect([x + 5.5, cy - 1.5], [x2 - 5.5, cy + 1.5], white).filled(true).build();
        }
        FlagSpec::BR => {
            dl.add_rect([x, y], [x2, y2], [0.04, 0.60, 0.24, 1.0]).filled(true).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_triangle([x + 2.5, cy], [cx, y + 2.0], [cx, y2 - 2.0], [0.98, 0.84, 0.05, 1.0])
                .filled(true)
                .build();
            dl.add_triangle([x2 - 2.5, cy], [cx, y + 2.0], [cx, y2 - 2.0], [0.98, 0.84, 0.05, 1.0])
                .filled(true)
                .build();
            dl.add_circle([cx, cy], 2.4, [0.05, 0.18, 0.52, 1.0]).filled(true).build();
        }
        FlagSpec::CA => {
            dl.add_rect([x, y], [x2, y2], white).filled(true).build();
            dl.add_rect([x, y], [x + w * 0.26, y2], [0.84, 0.10, 0.16, 1.0]).filled(true).build();
            dl.add_rect([x2 - w * 0.26, y], [x2, y2], [0.84, 0.10, 0.16, 1.0]).filled(true).build();
            dl.add_circle([x + w * 0.5, y + h * 0.5], 2.6, [0.84, 0.10, 0.16, 1.0]).filled(true).build();
        }
        FlagSpec::KR => {
            dl.add_rect([x, y], [x2, y2], white).filled(true).build();
            dl.add_circle([x + w * 0.5, y + h * 0.5 - 0.7], 2.7, [0.80, 0.12, 0.18, 1.0]).filled(true).build();
            dl.add_circle([x + w * 0.5, y + h * 0.5 + 0.7], 2.3, [0.05, 0.26, 0.65, 1.0]).filled(true).build();
        }
        FlagSpec::EU => {
            dl.add_rect([x, y], [x2, y2], [0.04, 0.20, 0.58, 1.0]).filled(true).build();
            dl.add_circle([x + w * 0.5, y + h * 0.5], 4.0, [0.98, 0.82, 0.10, 1.0]).thickness(1.3).build();
        }
        FlagSpec::Local => {
            dl.add_rect([x, y], [x2, y2], [0.12, 0.32, 0.36, 1.0]).filled(true).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_rect([cx - 4.0, cy - 2.5], [cx + 4.0, cy + 2.5], [0.25, 0.92, 0.78, 1.0])
                .thickness(1.2)
                .build();
        }
        FlagSpec::Global => {
            dl.add_rect([x, y], [x2, y2], [0.10, 0.34, 0.56, 1.0]).filled(true).build();
            let cx = x + w * 0.5;
            let cy = y + h * 0.5;
            dl.add_circle([cx, cy], 4.5, [0.35, 0.82, 0.98, 1.0]).thickness(1.1).build();
            dl.add_line([x + 4.0, cy], [x2 - 4.0, cy], [0.35, 0.82, 0.98, 1.0]).thickness(1.0).build();
        }
    }

    dl.add_rect([x, y], [x2, y2], [0.05f32, 0.06, 0.08, 0.85]).thickness(1.0).build();
    dl.add_rect([x, y], [x2, y2], [1.0f32, 1.0, 1.0, 0.18]).thickness(1.0).build();
}

/// Draws the 20x14 graphical country flag followed by the ISO code and returns horizontal width.
pub fn draw_flag_and_code(ui: &Ui, pos: [f32; 2], country: CountryCode) -> f32 {
    draw_country_flag(ui, [pos[0], pos[1] + 1.0], country);
    let code = country.code();
    let dl = ui.get_window_draw_list();
    dl.add_text([pos[0] + FLAG_W + 4.0, pos[1]], [0.68f32, 0.78, 0.90, 1.0], code);
    let code_w = ui.calc_text_size(code)[0];
    FLAG_W + 4.0 + code_w + 6.0
}
