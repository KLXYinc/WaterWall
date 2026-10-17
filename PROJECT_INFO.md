# WaterWall — Project Information

## 1. Overview
**WaterWall** is a visual Linux firewall, per-application network inspector, and traffic proxy/VPN controller built with Rust and Dear ImGui.

Unlike traditional command-line firewalls or opaque background services, WaterWall provides real-time visibility into every application communicating over the network, monitors live upload/download bandwidth, logs destination IPs and domains, and allows granular, per-app or global blocking and proxy/VPN routing.

---

## 2. Core Objectives & Capabilities

### Phase 1: Real-time App Discovery & Traffic Monitoring
- **Process & Socket Enumeration**: Scans `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/[pid]/fd` to map open sockets and inodes directly to process IDs.
- **Identical Program Aggregation**: Groups instances of the same program running multiple times into one unified entry with its instance count in parentheses (e.g. `Discord (2)`, `opencode (21)`, `sccache (67)`, `postgres (11)`).
- **Process Details**: Binary name, PID, instance count, list of all child PIDs, executable path, and command line.
- **Bandwidth Measurement**: Instantaneous upload/download speed (KB/s, MB/s) derived from process `/proc/[pid]/io` counters and historical throughput ring buffers.
- **Cumulative Accounting**: Total bytes transferred (sent & received) per application and system-wide.

### Phase 2: Connection Inspection & Telemetry
- **Endpoint Inspection**: Displays remote IP, remote port, local binding, protocol (`TCP`, `UDP`), and socket lifecycle state (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`).
- **Domain Attribution**: Asynchronous reverse DNS worker thread resolves remote IPs to human-readable domain names with a non-blocking in-memory cache.
- **IP Geolocation & Organization Classification**:
  - Classifies IP addresses into countries and cloud/service providers (e.g., Cloudflare CDN, Google Cloud / YouTube, Telegram Messenger, Valve/Steam, AWS, Hetzner, OVH, Loopback Interface, Private LAN).
  - Displays country and location flags (`🌐`, `🇺🇸`, `🇳🇱`, `🇩🇪`, `🇫🇷`, `🏠`).
- **Accurate Traffic Type Classification**:
  - Classifies network streams into real GlassWire-level protocol descriptions: `HTTPS`, `HTTP`, `QUIC (HTTP/3)`, `DNS`, `mDNS`, `SSDP`, `LLMNR`, `WireGuard`, `Discord/WebRTC`, `Steam`, `PostgreSQL`, `Redis`, `IPC`, `SSH`, etc.

### Phase 3: Interactive Firewall & Active Socket Termination
- **Per-Application Blocking**: 1-click **`[ 🛡️ ALLOWED ]`** / **`[ 🔥 BLOCKED ]`** toggle applies policy to all PIDs of the application.
- **Kernel Socket Termination**:
  - Actively aborts live connections via Linux Netlink `SOCK_DESTROY` / `ss -K` and TCP RST injection.
  - Sockets of blocked applications are immediately terminated rather than waiting for timeouts.
- **Privileged Background Daemon**:
  - Background daemon listener over Unix Domain Socket (`/run/waterwall.sock`, with `/tmp/waterwall.sock` dev fallback).
  - Enforces kernel-level socket termination and blocking policies.

### Phase 4: Per-Application & Global Proxy / VPN
- **Proxy Toggling**: 1-click **`[ ⇄ PROXY ]`** button to mark an application for redirection through SOCKS5, HTTP CONNECT, or WireGuard tunnels.
- **Split Tunneling**: Direct network access for regular apps while proxied apps are routed through the tunnel.

### Phase 5: Visual GlassWire GUI Dashboard & Flow Graph
- **Tab 1: Usage Dashboard (GlassWire Styled [Image 1])**:
  - Circular doughnut ring chart with incoming (yellow/amber) and outgoing (coral/pink) segments.
  - Formatted data readout in center and underneath.
  - Vertical External vs. Local meter bars.
  - **Apps Column**:
    - **"All" Entry** at the top showing total aggregate traffic across all applications.
    - Grouped application list with real Linux icons (from `.desktop` files, hicolor themes, and Flatpak directories).
    - Interactive selection: Clicking an application filters Column 2 (Hosts) and Column 3 (Traffic Type) specifically for that app.
  - **Hosts Column**:
    - Displays destination domain name, location flag, exact remote IP:Port readout, organization name, and progress bar.
  - **Traffic Type Column**:
    - Displays protocol badges (`[HTTPS]`, `[DNS]`, `[QUIC]`, etc.), full descriptions, socket count, port numbers, and accent progress bars.
  - **Bottom Timeline Scrubber**:
    - Mountain wave activity chart with time tick labels (`00 AM`, `3:00 AM`, `6:00 AM`, `9:00 AM`, `12:00 PM`, `3:00 PM`, `6:00 PM`, `9:00 PM`, `12`).
    - Draggable timeline scrubber handle.
- **Tab 2: Master-Detail Firewall Inspector ([Image 2])**:
  - Left panel: Searchable, sortable list of applications with emerald-green selection highlight.
  - Right panel: Destination inspector showing where the app connects, PID details, active sockets, dedicated mountain wave activity chart, and 1-click Firewall Allow/Block/Proxy actions.
  - **`[ 🔗 Flow Graph ]` Button**: Instantly sends the selected application into the visual node graph canvas.
- **Tab 3: Traffic Monitor**:
  - 4-column connecting breakdown page (Apps, Hosts, Traffic Types, Countries/Locations) with live bottom scrubber.
- **Tab 4: Interactive Flow Graph**:
  - Verlet rope physics node canvas with custom network flow nodes:
    - `AppSource`: Monitored application endpoint.
    - `FirewallFilter`: In-memory allow/block and port filter.
    - `ProxyRouter`: SOCKS5 / WireGuard / Direct traffic router.
    - `RateLimiter`: Bandwidth throttle and QoS delay simulator.
    - `TrafficMonitor`: Real-time packet sparklines and wave telemetry.
    - `InternetGateway`: Public WAN gateway / blackhole drop sink.
  - Interactive wiring: Drag ropes between pins to connect apps to filters, monitors, and gateways.

---

## 3. Technology Stack

| Layer | Component | Description |
|---|---|---|
| **Language** | Rust 2021 | Memory-safe, high-performance systems language |
| **GUI Framework** | Dear ImGui (`imgui-rs` + vendored C++ engine) | Immediate-mode UI with custom rope-physics node graph |
| **Windowing & GL** | `winit` 0.30 + `glutin` 0.32 + `glow` 0.14 | Wayland & X11 native windowing and hardware-accelerated OpenGL |
| **Kernel Networking** | `procfs` + Netlink `SOCK_DESTROY` / `ss -K` | Active socket observation, mapping, and kernel connection termination |
| **Icons & Assets** | `png = "0.17"` + Linux XDG / Flatpak spec | Resolves and renders real desktop icons directly into GPU texture memory |
| **IPC & Daemon** | Unix Domain Sockets (`/run/waterwall.sock`) | Secure communication between unprivileged GUI and privileged daemon |
| **DNS Engine** | Asynchronous reverse DNS worker thread | Non-blocking host domain attribution and caching |

---

## 4. CLI Modes

- `cargo run`: Launches the visual Dear ImGui GUI dashboard.
- `cargo run -- --probe`: Probes active network processes, speeds, and live sockets in terminal mode.
- `cargo run -- --daemon`: Starts the background privileged IPC daemon server on `/run/waterwall.sock`.
- `cargo run -- --help`: Displays the help menu.
