use crate::sys;
use crate::Ui;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Connected { from: i32, to: i32 },
    Removed { link: i32 },
    Focused { node: i32 },
    RmbNode { node: i32 },
    RmbCanvas { x: i32, y: i32 },
    InsertNode { node: i32, link: i32 },
    RopeKindChanged { link: i32, kind: i32 },
    CountryClicked { code: [u8; 2] },
}
pub fn begin(ui: &Ui, id: &str, size: [f32; 2]) -> bool {
    unsafe { sys::igNG_Begin(ui.scratch_txt(id), size[0], size[1]) }
}
pub fn end() {
    unsafe { sys::igNG_End() }
}
pub fn node_begin(
    ui: &Ui,
    id: i32,
    pos: &mut [f32; 2],
    width: f32,
    content_height: f32,
    title: &str,
    accent: [f32; 4],
) {
    unsafe {
        sys::igNG_NodeBegin(
            id,
            pos.as_mut_ptr(),
            width,
            content_height,
            ui.scratch_txt(title),
            accent[0],
            accent[1],
            accent[2],
            accent[3],
        );
    }
}
pub fn node_pin(ui: &Ui, id: i32, name: &str, color: [f32; 4], is_input: bool) {
    unsafe {
        sys::igNG_NodePin(
            id,
            ui.scratch_txt(name),
            color[0],
            color[1],
            color[2],
            color[3],
            is_input,
        );
    }
}
pub fn node_widget_row(height: f32) -> [f32; 4] {
    let mut rect = [0.0f32; 4];
    unsafe { sys::igNG_NodeWidgetRow(height, rect.as_mut_ptr()) };
    rect
}
pub fn node_end() {
    unsafe { sys::igNG_NodeEnd() }
}
pub fn link(link_id: i32, from_pin: i32, to_pin: i32) {
    unsafe { sys::igNG_Link(link_id, from_pin, to_pin) }
}
pub fn link_flow(
    ui: &Ui,
    link_id: i32,
    from_pin: i32,
    to_pin: i32,
    flow_intensity: f32,
    label: &str,
) {
    unsafe {
        sys::igNG_LinkFlow(
            link_id,
            from_pin,
            to_pin,
            flow_intensity,
            ui.scratch_txt(label),
        )
    }
}
pub fn set_link_kind(link_id: i32, kind: i32) {
    unsafe { sys::igNG_SetLinkKind(link_id, kind) }
}
pub fn get_link_kind(link_id: i32) -> i32 {
    unsafe { sys::igNG_GetLinkKind(link_id) }
}
pub fn clear_world_targets() {
    unsafe { sys::igNG_ClearWorldTargets() }
}
pub fn push_world_target(
    ui: &Ui,
    code: [u8; 2],
    intensity: f32,
    pkt_rate: f32,
    label: &str,
) {
    let code_u16 = ((code[0] as i32) << 8) | (code[1] as i32);
    unsafe {
        sys::igNG_PushWorldTarget(
            code_u16,
            intensity,
            pkt_rate,
            ui.scratch_txt(label),
        )
    }
}
pub fn pop_event() -> Option<Event> {
    let mut a = 0i32;
    let mut b = 0i32;
    match unsafe { sys::igNG_PopEvent(&mut a, &mut b) } {
        1 => Some(Event::Connected { from: a, to: b }),
        2 => Some(Event::Removed { link: a }),
        3 => Some(Event::Focused { node: a }),
        4 => Some(Event::RmbNode { node: a }),
        5 => Some(Event::RmbCanvas { x: a, y: b }),
        6 => Some(Event::InsertNode { node: a, link: b }),
        7 => Some(Event::RopeKindChanged { link: a, kind: b }),
        8 => Some(Event::CountryClicked {
            code: [((a >> 8) & 0xFF) as u8, (a & 0xFF) as u8],
        }),
        _ => None,
    }
}
pub fn set_pan(pan: [f32; 2]) {
    unsafe { sys::igNG_SetPan(pan[0], pan[1]) }
}
pub fn pan() -> [f32; 2] {
    let mut out = [0.0f32; 2];
    unsafe { sys::igNG_GetPan(out.as_mut_ptr()) };
    out
}
pub fn row_height() -> f32 {
    unsafe { sys::igNG_RowHeight() }
}
pub fn reset_interaction() {
    unsafe { sys::igNG_ResetInteraction() }
}
pub fn pin_pos(pin_id: i32) -> Option<[f32; 2]> {
    let mut out = [0.0f32; 2];
    let ok = unsafe { sys::igNG_GetPinPos(pin_id, out.as_mut_ptr()) };
    if ok {
        Some(out)
    } else {
        None
    }
}
pub fn free_rope_count() -> i32 {
    unsafe { sys::igNG_FreeRopeCount() }
}
pub fn free_rope_center(index: i32) -> Option<[f32; 2]> {
    let mut out = [0.0f32; 2];
    let ok = unsafe { sys::igNG_FreeRopeCenter(index, out.as_mut_ptr()) };
    if ok {
        Some(out)
    } else {
        None
    }
}
