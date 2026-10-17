use crate::gui::theme;

#[derive(Copy, Clone)]
pub struct Pin {
    pub id: i32,
    pub name: &'static str,
    pub color: [f32; 4],
    pub is_input: bool,
}

impl Pin {
    pub fn input(id: i32, name: &'static str) -> Self {
        Self {
            id,
            name,
            color: theme::PIN_INPUT,
            is_input: true,
        }
    }

    pub fn input_colored(id: i32, name: &'static str, color: [f32; 4]) -> Self {
        Self {
            id,
            name,
            color,
            is_input: true,
        }
    }

    pub fn output(id: i32, name: &'static str) -> Self {
        Self {
            id,
            name,
            color: theme::PIN_OUTPUT,
            is_input: false,
        }
    }

    pub fn output_colored(id: i32, name: &'static str, color: [f32; 4]) -> Self {
        Self {
            id,
            name,
            color,
            is_input: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Link {
    pub id: i32,
    pub from: i32,
    pub to: i32,
    pub flow_intensity: f32,
    pub rope_kind: i32,
    pub kind_synced: bool,
    pub label: String,
}

pub fn rope_kind_name(kind: i32) -> &'static str {
    match kind.rem_euclid(8) {
        0 => "Physics Cable (Speed & Volume)",
        1 => "Hard Trace (90° & 45° Auto-Corner)",
        2 => "Straight Taut Line",
        3 => "Smooth Thermal Heatmap Cable",
        4 => "Dual-Lane Split (Down ▼ / Up ▲)",
        5 => "Real Packet Stream Pulses",
        6 => "Live Oscilloscope Wave",
        7 => "Multi-Strand Socket Fiber",
        _ => "Physics Cable",
    }
}

pub const fn pin_id(node_id: i32, slot: i32) -> i32 {
    node_id * 100 + slot
}
