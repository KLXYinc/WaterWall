# WaterWall — Development & Implementation Plan

This document outlines the step-by-step roadmap and implementation status for WaterWall.

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│                   WaterWall GUI Client                 │
│  (Unprivileged user process: ImGui + Winit + Glow)     │
│                                                        │
│  [Tab 1: Usage Dashboard (GlassWire [Image 1])]        │
│    - Circular Doughnut Ring Chart (In/Out & Total)     │
│    - External vs. Local traffic meter bars             │
│    - Interactive Apps column with "All" top entry      │
│    - Filtered Hosts column with exact IP:Port & flags  │
│    - Filtered Traffic Types with accurate protocol IDs │
│    - Live mountain wave timeline & draggable scrubber  │
│                                                        │
│  [Tab 2: Firewall & Live Inspector (GlassWire [Image 2])]│
│    - Master-detail view: Left app list, right panel   │
│    - 1-click [ 🔥 BLOCKED ] & [ ⇄ PROXY ] toggles      │
│    - App destination IP inspector & dedicated wave graph│
│    - 1-click [ 🔗 Flow Graph ] to send app to canvas   │
│                                                        │
│  [Tab 3: Traffic Monitor]                              │
│    - 4-column connecting breakdown page                │
│                                                        │
│  [Tab 4: Interactive Flow Graph]                       │
│    - App Nodes -> Firewall Rule Nodes -> Proxy Nodes  │
│    - Verlet rope physics & live packet flow visuals    │
└──────────────────────────┬─────────────────────────────┘
                           │ Unix Domain Socket IPC (/run/waterwall.sock)
┌──────────────────────────▼─────────────────────────────┐
│                  WaterWall Daemon (root)               │
│                                                        │
│  - Socket & Process Inode Tracker (procfs / Netlink)   │
│  - In-Memory Per-App Rule Database (Zero firewall clutter)
│  - Active Kernel Socket Terminator (SOCK_DESTROY/ss -K)│
│  - Real-time Throughput & Bandwidth Meter              │
│  - SOCKS5 / HTTP / WireGuard Proxy Engine              │
└────────────────────────────────────────────────────────┘
```

---

## Implementation Status

### Phase 1: Real-Time Process & Network Discovery Engine — [COMPLETED]
- [x] Query Linux `/proc/net/{tcp,tcp6,udp,udp6}` for live sockets and inodes.
- [x] Scan `/proc/[pid]/fd/` to map socket inodes directly to process IDs.
- [x] Resolve PID metadata: binary name, executable path, process title, cmdline.
- [x] **Group identical programs running multiple times** into one entry with count: e.g. `Discord (2)`, `opencode (21)`, `sccache (67)`, `postgres (11)`.
- [x] Calculate instantaneous upload & download throughput from process `/proc/[pid]/io` counters.
- [x] Maintain historical bandwidth ring buffers for mountain wave sparklines and timeline charts.
- [x] Asynchronous reverse DNS worker thread resolving remote IPs to human-readable domain names.
- [x] Comprehensive IP geolocation and organization classification (Cloudflare, Google, Telegram, Valve, AWS, etc.).

### Phase 2: GUI Dashboard & Live Inspector — [COMPLETED]
- [x] **Tab 1: GlassWire Usage Dashboard ([Image 1])**:
  - Circular doughnut ring chart with yellow/amber incoming and coral/pink outgoing arcs.
  - External vs. Local vertical meter bars with byte readouts.
  - **"All" Entry** above the app list showing aggregate metrics.
  - Interactive selection: Clicking an application filters Column 2 (Hosts) and Column 3 (Traffic Type) to show that specific application's connections and protocols.
  - Hosts column displays country flag, domain name, exact remote IP:Port readout, and organization.
  - Traffic Types column accurately classifies protocols (`HTTPS`, `HTTP`, `QUIC`, `DNS`, `mDNS`, `WireGuard`, `Discord/WebRTC`, `Steam`, `IPC`, `Postgres`, etc.).
  - Bottom timeline wave chart with time ticks (`00 AM`, `3:00 AM`, `6:00 AM`, `9:00 AM`, `12:00 PM`, `3:00 PM`, `6:00 PM`, `9:00 PM`, `12`) and draggable scrubber.
- [x] **Tab 2: Master-Detail Firewall Inspector ([Image 2])**:
  - Left panel: Searchable, sortable list of applications with emerald-green selection highlight.
  - Right panel: Destination inspector showing where the app connects, PID details, active sockets, dedicated mountain wave activity chart, and 1-click Firewall Allow/Block/Proxy actions.
  - **`[ 🔗 Flow Graph ]` Button**: Instantly sends the selected application into the visual node graph canvas.
- [x] **Tab 3: Traffic Monitor**:
  - 4-column connecting breakdown page (Apps, Hosts, Traffic Types, Countries/Locations) with live bottom scrubber.
- [x] **Real Linux Application Icons**:
  - Extracts and resolves icons from `.desktop` files, hicolor themes, and Flatpak directories directly into GPU texture memory via OpenGL and `glow`.

### Phase 3: Custom Per-Application Firewall Engine — [COMPLETED]
- [x] In-memory per-application rule database (zero system firewall pollution).
- [x] 1-click **`[ 🛡️ ALLOWED ]`** / **`[ 🔥 BLOCKED ]`** toggle applied across all PIDs of the application.
- [x] **Kernel Socket Termination Engine**:
  - Actively aborts live connections via Linux Netlink `SOCK_DESTROY` / `ss -K` and TCP RST injection.
  - Sockets of blocked applications are immediately terminated upon clicking block.

### Phase 4: Per-Application & Global Proxy / VPN — [COMPLETED]
- [x] 1-click **`[ ⇄ PROXY ]`** toggle to mark an application for proxy routing.
- [x] Proxy routing flags supported across all application instances.

### Phase 5: Visual Node Graph Integration — [COMPLETED]
- [x] Verlet rope physics node canvas with custom network flow nodes:
  - `AppSource`: Monitored application endpoint.
  - `FirewallFilter`: In-memory allow/block and port filter.
  - `ProxyRouter`: SOCKS5 / WireGuard / Direct traffic router.
  - `RateLimiter`: Bandwidth throttle and QoS delay simulator.
  - `TrafficMonitor`: Real-time packet sparklines and wave telemetry.
  - `InternetGateway`: Public WAN gateway / blackhole drop sink.
- [x] Interactive wiring: Drag ropes between pins to connect apps to filters, monitors, and gateways.
- [x] 1-click **"Send to Flow Graph"** button in Firewall inspector to inject any app directly into the canvas.

### Phase 6: Service / Daemon Architecture & Tests — [COMPLETED]
- [x] Privileged background daemon listener over Unix Domain Socket (`/run/waterwall.sock` with `/tmp/waterwall.sock` dev fallback).
- [x] CLI flags in `src/main.rs`:
  - `cargo run`: Launches the visual Dear ImGui GUI dashboard.
  - `cargo run -- --probe`: Probes active network processes, speeds, and live sockets in terminal mode.
  - `cargo run -- --daemon`: Runs background privileged IPC daemon.
  - `cargo run -- --help`: Prints usage help.
- [x] 8/8 automated unit tests passing.
