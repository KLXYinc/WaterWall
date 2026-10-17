use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use glow::HasContext;
use imgui::TextureId;

pub struct IconManager {
    /// Cache of app name -> TextureId (or None if not found/failed to load)
    textures: HashMap<String, Option<TextureId>>,
    /// Keep track of native GL textures so we can free them on drop
    gl_textures: Vec<glow::Texture>,
    /// Desktop icon map: app identifier -> icon file path
    desktop_icon_cache: HashMap<String, PathBuf>,
}

impl Default for IconManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IconManager {
    pub fn new() -> Self {
        let mut manager = Self {
            textures: HashMap::new(),
            gl_textures: Vec::new(),
            desktop_icon_cache: HashMap::new(),
        };
        manager.scan_desktop_icons();
        manager
    }

    /// Scans standard Linux desktop directories to build a map of AppName -> IconPath
    fn scan_desktop_icons(&mut self) {
        let app_dirs = [
            "/usr/share/applications",
            "/usr/local/share/applications",
            "/var/lib/flatpak/exports/share/applications",
        ];

        // Also check user's local directory
        let home = std::env::var("HOME").unwrap_or_default();
        let user_dirs = [
            format!("{home}/.local/share/applications"),
            format!("{home}/.local/share/flatpak/exports/share/applications"),
        ];

        for dir in app_dirs.iter().map(Path::new).chain(user_dirs.iter().map(Path::new)) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("desktop") {
                        self.parse_desktop_file(&path);
                    }
                }
            }
        }
    }

    fn parse_desktop_file(&mut self, path: &Path) {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut app_name = String::new();
        let mut exec_name = String::new();
        let mut icon_val = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') && line != "[Desktop Entry]" {
                break; // Stop at other desktop groups
            }

            if let Some(val) = line.strip_prefix("Name=") {
                if app_name.is_empty() {
                    app_name = val.trim().to_lowercase();
                }
            } else if let Some(val) = line.strip_prefix("Exec=") {
                if exec_name.is_empty() {
                    // Extract binary name from Exec (e.g. "Exec=firefox %u" -> "firefox")
                    let bin = val.split_whitespace().next().unwrap_or("");
                    let bin_clean = Path::new(bin).file_name().and_then(|s| s.to_str()).unwrap_or(bin);
                    exec_name = bin_clean.to_lowercase();
                }
            } else if let Some(val) = line.strip_prefix("Icon=") {
                if icon_val.is_empty() {
                    icon_val = val.trim().to_string();
                }
            }
        }

        if !icon_val.is_empty() {
            if let Some(icon_path) = find_icon_file(&icon_val) {
                if !app_name.is_empty() {
                    self.desktop_icon_cache.insert(app_name.clone(), icon_path.clone());
                }
                if !exec_name.is_empty() {
                    self.desktop_icon_cache.insert(exec_name.clone(), icon_path.clone());
                }

                // Also map desktop file stem (e.g. "com.discordapp.Discord" or "librewolf")
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    self.desktop_icon_cache.insert(stem.to_lowercase(), icon_path);
                }
            }
        }
    }

    /// Retrieve or lazily load the icon texture for an application
    pub fn get_or_load_icon(&mut self, gl: &glow::Context, name: &str, exe_path: &str) -> Option<TextureId> {
        let key = name.to_lowercase();

        if let Some(&cached) = self.textures.get(&key) {
            return cached;
        }

        // Try to find icon file
        let icon_file = self.resolve_icon_path(&key, exe_path);

        let texture_id = if let Some(path) = icon_file {
            self.load_texture_from_file(gl, &path)
        } else {
            None
        };

        self.textures.insert(key, texture_id);
        texture_id
    }

    fn resolve_icon_path(&self, key: &str, exe_path: &str) -> Option<PathBuf> {
        // 1. Check cached desktop map by name
        if let Some(path) = self.desktop_icon_cache.get(key) {
            return Some(path.clone());
        }

        // 2. Try by binary stem from exe_path
        if !exe_path.is_empty() {
            let exe_name = Path::new(exe_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            if let Some(path) = self.desktop_icon_cache.get(&exe_name) {
                return Some(path.clone());
            }

            if let Some(path) = find_icon_file(&exe_name) {
                return Some(path);
            }
        }

        // 3. Normalized names & aliases
        let aliases: &[&str] = if key.contains("discord") {
            &["discord", "com.discordapp.discord"]
        } else if key.contains("ayugram") {
            &["com.ayugram.desktop", "ayugram", "telegram"]
        } else if key.contains("telegram") {
            &["telegram", "org.telegram.desktop", "com.ayugram.desktop"]
        } else if key.contains("steam") {
            &["steam", "steamwebhelper"]
        } else if key.contains("librewolf") {
            &["librewolf", "io.gitlab.librewolf-community"]
        } else if key.contains("firefox") {
            &["firefox", "org.mozilla.firefox"]
        } else if key.contains("chrome") {
            &["google-chrome", "google-chrome-stable", "chromium"]
        } else if key.contains("spotify") {
            &["spotify", "com.spotify.Client"]
        } else if key.contains("code") || key.contains("opencode") {
            &["visual-studio-code", "code", "vscode", "vscodium"]
        } else {
            &[]
        };

        for alias in aliases {
            if let Some(path) = self.desktop_icon_cache.get(*alias) {
                return Some(path.clone());
            }
            if let Some(path) = find_icon_file(alias) {
                return Some(path);
            }
        }

        // 4. Direct search by key name
        find_icon_file(key)
    }

    fn load_texture_from_file(&mut self, gl: &glow::Context, path: &Path) -> Option<TextureId> {
        let file = fs::File::open(path).ok()?;
        let mut decoder = png::Decoder::new(file);
        decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
        let mut reader = decoder.read_info().ok()?;
        let mut buf = vec![0; reader.output_buffer_size()];
        let info = reader.next_frame(&mut buf).ok()?;
        let bytes = &buf[..info.buffer_size()];

        let width = info.width;
        let height = info.height;

        let gl_format = match info.color_type {
            png::ColorType::Rgba => glow::RGBA,
            png::ColorType::Rgb => glow::RGB,
            png::ColorType::GrayscaleAlpha => glow::LUMINANCE_ALPHA,
            png::ColorType::Grayscale => glow::LUMINANCE,
            _ => glow::RGBA,
        };

        unsafe {
            let gl_tex = gl.create_texture().ok()?;
            gl.bind_texture(glow::TEXTURE_2D, Some(gl_tex));

            gl.tex_image_2d(
                glow::TEXTURE_2D,
                0,
                gl_format as i32,
                width as i32,
                height as i32,
                0,
                gl_format,
                glow::UNSIGNED_BYTE,
                Some(bytes),
            );

            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MIN_FILTER, glow::LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_MAG_FILTER, glow::LINEAR as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE as i32);
            gl.tex_parameter_i32(glow::TEXTURE_2D, glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE as i32);

            gl.bind_texture(glow::TEXTURE_2D, None);

            let raw_id = gl_tex.0.get();
            self.gl_textures.push(gl_tex);

            Some(TextureId::from(raw_id as usize))
        }
    }
}

/// Helper to search for an icon PNG in standard directories
fn find_icon_file(icon_name: &str) -> Option<PathBuf> {
    // If it's already an existing file path
    let direct_path = Path::new(icon_name);
    if direct_path.is_file() {
        return Some(direct_path.to_path_buf());
    }

    let clean_name = icon_name.trim_end_matches(".png").trim_end_matches(".svg");

    let home = std::env::var("HOME").unwrap_or_default();
    let search_roots = [
        "/usr/share/icons/hicolor",
        "/usr/share/pixmaps",
        "/var/lib/flatpak/appstream/flathub/x86_64",
        "/var/lib/flatpak/app",
        &format!("{home}/.local/share/icons"),
    ];

    let preferred_resolutions = [
        "128x128", "64x64", "48x48", "256x256", "32x32", "512x512", "scalable",
    ];

    // Priority 1: hicolor theme apps
    for res in preferred_resolutions {
        let p = PathBuf::from(format!("/usr/share/icons/hicolor/{res}/apps/{clean_name}.png"));
        if p.is_file() {
            return Some(p);
        }
    }

    // Priority 2: pixmaps
    let p_pixmap = PathBuf::from(format!("/usr/share/pixmaps/{clean_name}.png"));
    if p_pixmap.is_file() {
        return Some(p_pixmap);
    }

    // Priority 3: Flatpak appstream directories
    for root in &search_roots {
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("icons").join("128x128").join(format!("{clean_name}.png"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    // Priority 4: Search for matching png files in Flatpak app directory
    if let Ok(entries) = fs::read_dir("/var/lib/flatpak/app") {
        for entry in entries.flatten() {
            let candidate = entry.path().join("x86_64/stable/active/files/share/app-info/icons/flatpak/128x128").join(format!("{clean_name}.png"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}
