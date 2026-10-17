use std::io::Write;
use std::process::{Command, Stdio};

pub struct LinuxClipboardBackend;

impl imgui::ClipboardBackend for LinuxClipboardBackend {
    fn get(&mut self) -> Option<String> {
        read_system_clipboard()
    }

    fn set(&mut self, value: &str) {
        write_system_clipboard(value);
    }
}

pub fn read_system_clipboard() -> Option<String> {
    let cmds: &[(&str, &[&str])] = &[
        ("wl-paste", &["--no-newline"]),
        ("xclip", &["-selection", "clipboard", "-o"]),
        ("xsel", &["--clipboard", "--output"]),
    ];
    for (bin, args) in cmds {
        if let Ok(out) = Command::new(bin).args(*args).output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

pub fn write_system_clipboard(text: &str) {
    let cmds: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard", "-i"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (bin, args) in cmds {
        if let Ok(mut child) = Command::new(bin)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
            return;
        }
    }
}
