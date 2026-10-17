# WaterWall

A Rust GUI project using **Dear ImGui** through the [`imgui`](https://crates.io/crates/imgui) bindings (`imgui-rs`) — with an immediate-mode **node editor** featuring sagging, physical verlet-simulated ropes.

Copied and adapted from the Dear ImGui setup in `AudioMixer`.

---

## Architecture & Layout

All GUI-related modules are organized cleanly inside `src/gui/` and re-exported at the root of `src/`:

```
WaterWall/
├── Cargo.toml                    # Package manifest & vendored crate patches
├── .gitignore                    # Build artifacts & imgui.ini ignore rules
├── imgui/                        # Dear ImGui C++ fork with custom node graph module
├── vendor/
│   ├── imgui/                    # Vendored Rust imgui crate
│   └── imgui-sys/                # Vendored Rust imgui-sys crate (FFI bindings)
└── src/
    ├── main.rs                   # Winit event loop & application handler
    ├── graphics.rs               # (re-export) OpenGL, Winit & ImGui renderer
    ├── theme.rs                  # (re-export) Theme colors & styling
    ├── app.rs                    # (re-export) Main application shell
    ├── nodes.rs                  # (re-export) Node & Pin definitions
    ├── graph.rs                  # (re-export) Graph model & link management
    └── gui/
        ├── mod.rs                # GUI module bundle
        ├── graphics.rs           # Window creation (Winit), OpenGL context (Glutin/Glow), ImGui AutoRenderer
        ├── theme.rs              # Palette, pin colors, backdrop and window background
        ├── app.rs                # Application window layout and state
        ├── canvas.rs             # Node graph canvas rendering and interaction
        ├── toolbar.rs            # Top bar actions (+ Add, Reset, Quit)
        ├── graph/
        │   └── mod.rs            # Graph model, link declarations, event handling
        └── nodes/
            ├── mod.rs            # NodeKind enum, categories, default items
            ├── node.rs           # Node structure, widgets layout & rendering
            ├── pin.rs            # Pin and Link structures
            └── item.rs           # Sliders, checkboxes, pins, waveform plots
```

---

## Features

- **Windowing & Rendering Backend**:
  - `winit` 0.30 (X11 & Wayland support)
  - `glutin` 0.32 + `glow` 0.14 for OpenGL context management
  - `imgui-winit-support` + `imgui-glow-renderer`
  - High-DPI auto-scaling
- **Dear ImGui Node Engine**:
  - Immediate-mode node graph layout (`imgui::node_graph`)
  - Verlet-integrated rope connections with gravity, sagging, and lateral flutter
  - Catmull-Rom smoothed spline rendering with drop shadows
  - Interactive link dragging, pin snapping, connection drops on node bodies
  - Blender-style right-click drag cutting line
  - Dropped / cut ropes tumble and fall off canvas under physics
  - Middle-mouse canvas panning
  - Right-click canvas popup menu to spawn new nodes

---

## Building and Running

### Prerequisites

Ensure you have a C++ compiler (`gcc` or `clang`), `pkg-config`, and OpenGL libraries installed.

### Build

```sh
cargo build
```

### Run

```sh
cargo run
```
