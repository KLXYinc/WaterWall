use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const AUTH_ACK_ENV: &str = "WATERWALL_AUTH_ACK";
const NO_SUDO_ENV: &str = "WATERWALL_NO_SUDO";

/// Returns `true` if the current process has effective root privileges (`euid == 0`).
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Attempts optional `sudo` (or `pkexec` if no TTY is attached) on startup so WaterWall can
/// inspect `/proc/<pid>/fd` and `/proc/<pid>/io` for all system-wide daemons and services.
///
/// If the user declines `sudo` (e.g. presses Ctrl+C, enters an empty/invalid password, or
/// cancels the Polkit prompt), this function returns `Ok(())` and WaterWall continues
/// normally in unprivileged User-Apps-Only mode.
pub fn try_optional_sudo_on_startup(args: &[String]) {
    // 1. If we are the elevated child process, write the auth acknowledgement marker immediately.
    if let Ok(ack_path) = env::var(AUTH_ACK_ENV) {
        let _ = fs::write(&ack_path, b"1");
        env::remove_var(AUTH_ACK_ENV);
    }

    // 2. Skip if already root, if --no-sudo was passed, or if we already attempted elevation.
    if is_elevated()
        || env::var_os(NO_SUDO_ENV).is_some()
        || args.iter().any(|a| a == "--no-sudo")
    {
        return;
    }

    let Ok(exe) = env::current_exe() else {
        return;
    };

    let ack_path = format!("/tmp/.waterwall_auth_{}", std::process::id());
    let _ = fs::remove_file(&ack_path);

    // Preserve GUI display, Wayland/X11 auth, runtime dir, and user home across sudo env_reset.
    let mut env_args: Vec<String> = vec![
        format!("{}={}", AUTH_ACK_ENV, ack_path),
        format!("{}=1", NO_SUDO_ENV),
    ];
    for key in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "USER",
        "PATH",
    ] {
        if let Ok(val) = env::var(key) {
            if !val.is_empty() {
                env_args.push(format!("{}={}", key, val));
            }
        }
    }

    let has_tty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };

    let mut cmd = if has_tty {
        println!(
            "WaterWall: Requesting optional sudo to capture network requests from system apps..."
        );
        println!("           (Press Ctrl+C to skip and monitor user apps only)");
        let mut c = Command::new("sudo");
        c.arg("env");
        c
    } else if Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        let mut c = Command::new("sudo");
        c.args(["-n", "env"]);
        c
    } else {
        let mut c = Command::new("pkexec");
        c.arg("env");
        c
    };

    cmd.args(&env_args);
    cmd.arg(&exe);
    cmd.args(args.iter().skip(1));

    // Ignore SIGINT in the parent while waiting so pressing Ctrl+C at the sudo prompt
    // cancels sudo and falls back to user mode instead of terminating WaterWall.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }

    let status = cmd.status();

    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }

    let auth_succeeded = Path::new(&ack_path).exists();
    let _ = fs::remove_file(&ack_path);

    if auth_succeeded {
        let code = status.ok().and_then(|s| s.code()).unwrap_or(0);
        std::process::exit(code);
    } else {
        eprintln!(
            "\nWaterWall: Sudo declined or unavailable — continuing with user apps only."
        );
    }
}
