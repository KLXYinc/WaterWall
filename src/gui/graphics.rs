use std::num::NonZeroU32;

use glow::HasContext;
use glutin::{
    config::ConfigTemplateBuilder,
    context::{ContextAttributesBuilder, NotCurrentGlContext, PossiblyCurrentContext},
    display::{GetGlDisplay, GlDisplay},
    surface::{GlSurface, Surface, SurfaceAttributesBuilder, SwapInterval, WindowSurface},
};
use imgui_glow_renderer::AutoRenderer;
use imgui_winit_support::{HiDpiMode, WinitPlatform};
use raw_window_handle::HasWindowHandle;
use winit::{
    dpi::LogicalSize,
    event_loop::ActiveEventLoop,
    window::{Window, WindowAttributes},
};

use super::theme;
use crate::utils::LinuxClipboardBackend;

pub const WINDOW_TITLE: &str = "WaterWall";
pub const INITIAL_WIDTH: u32 = 1280;
pub const INITIAL_HEIGHT: u32 = 800;

pub struct Graphics {
    pub window: Window,
    pub surface: Surface<WindowSurface>,
    pub context: PossiblyCurrentContext,
    pub renderer: AutoRenderer,
}

impl Graphics {
    pub fn new(
        event_loop: &ActiveEventLoop,
        imgui: &mut imgui::Context,
        platform: &mut WinitPlatform,
    ) -> Self {
        let window_attributes = WindowAttributes::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size(LogicalSize::new(INITIAL_WIDTH, INITIAL_HEIGHT));

        let (window, config) = glutin_winit::DisplayBuilder::new()
            .with_window_attributes(Some(window_attributes))
            .build(event_loop, ConfigTemplateBuilder::new(), |mut configs| {
                configs.next().expect("no suitable OpenGL config found")
            })
            .expect("failed to create an OpenGL window");

        let window = window.expect("glutin returned no window");

        let context_attributes =
            ContextAttributesBuilder::new().build(Some(window.window_handle().unwrap().as_raw()));
        let context = unsafe {
            config
                .display()
                .create_context(&config, &context_attributes)
                .expect("failed to create an OpenGL context")
        };

        let surface_attributes = SurfaceAttributesBuilder::<WindowSurface>::new()
            .with_srgb(Some(true))
            .build(
                window.window_handle().unwrap().as_raw(),
                NonZeroU32::new(INITIAL_WIDTH).unwrap(),
                NonZeroU32::new(INITIAL_HEIGHT).unwrap(),
            );
        let surface = unsafe {
            config
                .display()
                .create_window_surface(&config, &surface_attributes)
                .expect("failed to create an OpenGL surface")
        };

        let context = context
            .make_current(&surface)
            .expect("failed to make the OpenGL context current");

        surface
            .set_swap_interval(&context, SwapInterval::Wait(NonZeroU32::new(1).unwrap()))
            .expect("failed to set the swap interval");

        let gl = unsafe {
            glow::Context::from_loader_function_cstr(|symbol| {
                config.display().get_proc_address(symbol).cast()
            })
        };

        platform.attach_window(imgui.io_mut(), &window, HiDpiMode::Rounded);

        let font_candidates = [
            "/usr/share/fonts/Adwaita/AdwaitaSans-Regular.ttf",
            "/usr/share/fonts/TTF/Vera.ttf",
            "/usr/share/fonts/TTF/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ];
        let mut loaded_ttf = false;
        let hidpi = platform.hidpi_factor() as f32;
        for path in font_candidates {
            if let Ok(bytes) = std::fs::read(path) {
                imgui.fonts().add_font(&[imgui::FontSource::TtfData {
                    data: &bytes,
                    size_pixels: (14.5 * hidpi).round(),
                    config: None,
                }]);
                loaded_ttf = true;
                break;
            }
        }
        if !loaded_ttf {
            imgui
                .fonts()
                .add_font(&[imgui::FontSource::DefaultFontData { config: None }]);
        }

        imgui.io_mut().font_global_scale = (1.0 / platform.hidpi_factor()) as f32;
        imgui.set_clipboard_backend(LinuxClipboardBackend);

        let renderer = AutoRenderer::new(gl, imgui).expect("failed to create the ImGui renderer");

        Self {
            window,
            surface,
            context,
            renderer,
        }
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        if width > 0 && height > 0 {
            self.surface.resize(
                &self.context,
                NonZeroU32::new(width).unwrap(),
                NonZeroU32::new(height).unwrap(),
            );
        }
    }

    pub fn render_frame(
        &mut self,
        imgui: &mut imgui::Context,
        platform: &mut WinitPlatform,
        render_ui: impl FnOnce(&imgui::Ui, &glow::Context),
    ) {
        let [r, g, b] = theme::BACKDROP;
        unsafe {
            self.renderer.gl_context().clear_color(r, g, b, 1.0);
            self.renderer.gl_context().clear(glow::COLOR_BUFFER_BIT);
        }

        let ui = imgui.frame();
        render_ui(ui, self.renderer.gl_context());

        platform.prepare_render(ui, &self.window);
        let draw_data = imgui.render();

        self.renderer
            .render(draw_data)
            .expect("failed to render the ImGui draw lists");

        self.surface
            .swap_buffers(&self.context)
            .expect("failed to swap buffers");
    }
}
