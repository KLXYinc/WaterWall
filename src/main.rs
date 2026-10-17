pub mod gui;
pub mod net;
pub mod utils;

use std::time::Instant;

pub use gui::*;
use imgui_winit_support::WinitPlatform;
use winit::{
    application::ApplicationHandler,
    event::{Event, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop},
    window::WindowId,
};

struct App {
    imgui: imgui::Context,
    platform: WinitPlatform,
    ui: WaterWallApp,
    graphics: Option<Graphics>,
    last_frame: Instant,
}

impl App {
    fn new() -> Self {
        let mut imgui = imgui::Context::create();
        imgui.set_ini_filename(None);
        let platform = WinitPlatform::new(&mut imgui);

        Self {
            imgui,
            platform,
            ui: WaterWallApp::new(),
            graphics: None,
            last_frame: Instant::now(),
        }
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.graphics.is_none() {
            self.graphics = Some(Graphics::new(
                event_loop,
                &mut self.imgui,
                &mut self.platform,
            ));
        }
    }

    fn new_events(&mut self, _event_loop: &ActiveEventLoop, _cause: StartCause) {
        let now = Instant::now();
        self.imgui
            .io_mut()
            .update_delta_time(now.duration_since(self.last_frame));
        self.last_frame = now;
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.ui.should_exit {
            self.ui.shutdown();
            event_loop.exit();
            return;
        }

        if let Some(graphics) = self.graphics.as_ref() {
            self.platform
                .prepare_frame(self.imgui.io_mut(), &graphics.window)
                .expect("failed to prepare an ImGui frame");
            graphics.window.request_redraw();
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        match &event {
            WindowEvent::CloseRequested => {
                self.ui.shutdown();
                event_loop.exit();
                return;
            }
            WindowEvent::RedrawRequested => {
                if let Some(graphics) = self.graphics.as_mut() {
                    graphics.render_frame(&mut self.imgui, &mut self.platform, |ui, gl| {
                        self.ui.build(ui, gl);
                    });
                }
                return;
            }
            WindowEvent::Resized(size) => {
                if let Some(graphics) = self.graphics.as_mut() {
                    graphics.resize(size.width, size.height);
                }
            }
            _ => {}
        }

        if let Some(graphics) = self.graphics.as_ref() {
            self.platform.handle_event(
                self.imgui.io_mut(),
                &graphics.window,
                &Event::<()>::WindowEvent { window_id, event },
            );
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("WaterWall — Visual Linux Firewall, Network Monitor & Proxy Controller");
        println!();
        println!("USAGE:");
        println!("  waterwall [FLAGS]");
        println!();
        println!("FLAGS:");
        println!("  (none)        Launch the Dear ImGui visual dark-mode GUI dashboard");
        println!("  --probe       Sample and print live network processes, sockets, and destinations");
        println!("  --daemon      Run background privileged IPC daemon on /run/waterwall.sock");
        println!("  -h, --help    Print this help menu");
        println!();
        return Ok(());
    }

    if args.iter().any(|a| a == "--daemon") {
        println!("Starting WaterWall Background Privileged Daemon...");
        static GLOBAL_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

        extern "C" fn handle_sig(_: libc::c_int) {
            GLOBAL_RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        unsafe {
            libc::signal(libc::SIGINT, handle_sig as *const () as usize);
            libc::signal(libc::SIGTERM, handle_sig as *const () as usize);
        }

        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let r_clone = running.clone();
        std::thread::spawn(move || {
            while GLOBAL_RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            r_clone.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        net::run_daemon_server(running)?;
        return Ok(());
    }

    if args.iter().any(|a| a == "--probe" || a == "--dump" || a == "--list") {
        println!("WaterWall — Probing active network processes and connections...\n");
        let monitor = net::NetworkMonitor::new();
        // Give background scanner time to collect initial network and procfs samples
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let snapshot = monitor.snapshot();

        println!(
            "{:<8} {:<24} {:<12} {:<12} {:<14} {:<12} DESTINATIONS / DOMAINS",
            "PID", "PROCESS", "DOWN SPEED", "UP SPEED", "TOTAL USAGE", "SOCKETS"
        );
        println!("{}", "-".repeat(110));

        let mut apps = snapshot.apps;
        apps.sort_by(|a, b| b.download_speed.partial_cmp(&a.download_speed).unwrap());

        for app in &apps {
            let total_bytes = app.total_downloaded + app.total_uploaded;
            let dests: Vec<String> = app
                .connections
                .iter()
                .filter(|c| !c.remote_addr.ip().is_unspecified() && c.remote_addr.port() != 0)
                .take(3)
                .map(|c| {
                    if let Some(domain) = &c.domain {
                        format!("{}:{} ({})", c.remote_addr.ip(), c.remote_addr.port(), domain)
                    } else {
                        format!("{}:{}", c.remote_addr.ip(), c.remote_addr.port())
                    }
                })
                .collect();

            let dest_str = if dests.is_empty() {
                "Listening / Local".to_string()
            } else {
                dests.join(", ")
            };

            let display_name = app.display_name();
            println!(
                "{:<8} {:<24} {:<12} {:<12} {:<14} {:<12} {}",
                app.pid,
                if display_name.len() > 23 { &display_name[..23] } else { &display_name },
                net::format_speed(app.download_speed),
                net::format_speed(app.upload_speed),
                net::format_bytes(total_bytes),
                format!("{} ({})", app.connections.len(), app.active_connection_count()),
                dest_str
            );
        }

        println!("{}", "-".repeat(110));
        println!(
            "System Total:  ▼ {}   ▲ {}   (Session Total: {} ↓ / {} ↑)",
            net::format_speed(snapshot.system_download_speed),
            net::format_speed(snapshot.system_upload_speed),
            net::format_bytes(snapshot.session_total_download),
            net::format_bytes(snapshot.session_total_upload)
        );
        return Ok(());
    }

    let event_loop = EventLoop::new()?;
    let mut app = App::new();
    event_loop.run_app(&mut app)?;
    Ok(())
}
