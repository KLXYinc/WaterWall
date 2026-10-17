//! Hand-written FFI declarations for the local fork's node graph module
//! (`imgui/imgui_node_graph.h` / `.cpp`, included from `include_imgui_master.cpp`).
//!
//! Keep these signatures in sync with the `extern "C"` bridge at the bottom of
//! `imgui/imgui_node_graph.cpp`; there is no bindgen for this module.

use crate::cty::{c_char, c_float, c_int};

extern "C" {
    pub fn igNG_Begin(id: *const c_char, w: c_float, h: c_float) -> bool;
    pub fn igNG_End();
    pub fn igNG_NodeBegin(
        node_id: c_int,
        pos_xy: *mut c_float,
        width: c_float,
        content_h: c_float,
        title: *const c_char,
        r: c_float,
        g: c_float,
        b: c_float,
        a: c_float,
    );
    pub fn igNG_NodePin(
        pin_id: c_int,
        name: *const c_char,
        r: c_float,
        g: c_float,
        b: c_float,
        a: c_float,
        is_input: bool,
    );
    pub fn igNG_NodeWidgetRow(height: c_float, out_xywh: *mut c_float);
    pub fn igNG_NodeEnd();
    pub fn igNG_Link(link_id: c_int, from_pin: c_int, to_pin: c_int);
    pub fn igNG_LinkFlow(
        link_id: c_int,
        from_pin: c_int,
        to_pin: c_int,
        flow_intensity: c_float,
        label: *const c_char,
    );
    pub fn igNG_SetLinkKind(link_id: c_int, kind: c_int);
    pub fn igNG_GetLinkKind(link_id: c_int) -> c_int;
    pub fn igNG_ClearWorldTargets();
    pub fn igNG_PushWorldTarget(
        country_code_u16: c_int,
        intensity: c_float,
        pkt_rate: c_float,
        label: *const c_char,
    );
    pub fn igNG_PopEvent(a: *mut c_int, b: *mut c_int) -> c_int;
    pub fn igNG_SetPan(x: c_float, y: c_float);
    pub fn igNG_GetPan(out_xy: *mut c_float);
    pub fn igNG_RowHeight() -> c_float;
    pub fn igNG_ResetInteraction();
    pub fn igNG_GetPinPos(pin_id: c_int, out_xy: *mut c_float) -> bool;
    pub fn igNG_FreeRopeCount() -> c_int;
    pub fn igNG_FreeRopeCenter(index: c_int, out_xy: *mut c_float) -> bool;
}
