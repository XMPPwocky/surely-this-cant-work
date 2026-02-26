//! High-level Window client wrapper for GUI applications.
//!
//! Encapsulates the full window creation handshake (connect → CreateWindow →
//! GetInfo → GetFramebuffer → mmap) and double-buffer management into a
//! single `Window` struct.
//!
//! # Example
//! ```no_run
//! let mut win = rvos::Window::create(400, 300).expect("window");
//! // Draw into win.back_buffer_mut() ...
//! win.present();
//! // Poll events via win.event_channel().try_next_message()
//! ```

use crate::raw;
use crate::channel::Channel;
use crate::UserTransport;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
};
use rvos_wire::Never;

/// A connected window with double-buffered SHM framebuffer.
pub struct Window {
    /// Typed RPC client on the request channel.
    client: WindowClient<UserTransport>,
    /// Event channel for keyboard/mouse/close events.
    events: Channel<Never, WindowEvent>,
    /// Raw handle for the request channel (needed for poll_add).
    req_handle: usize,
    /// Window dimensions.
    width: u32,
    height: u32,
    stride: u32,
    /// Mapped framebuffer base (both buffers).
    fb_base: *mut u32,
    /// Pixels in each buffer (stride * height).
    pixels_per_buffer: usize,
    /// SHM handle (for cleanup).
    shm_handle: usize,
    /// Total mapped size in bytes.
    fb_mapped_size: usize,
    /// Which buffer is the current back buffer (0 or 1).
    current_back: u8,
    /// Monotonic swap sequence number.
    swap_seq: u32,
}

impl Window {
    /// Connect to the window service, create a window of the given size,
    /// and set up the double-buffered framebuffer.
    ///
    /// Pass `(0, 0)` for fullscreen.
    pub fn create(width: u32, height: u32) -> Result<Self, &'static str> {
        // 1. Connect to "window" service
        let win_ctl = crate::connect_to_service("window")
            .map_err(|_| "failed to connect to window service")?
            .into_raw_handle();

        // 2. CreateWindow handshake
        let mut ctl_ch =
            Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
        ctl_ch
            .send(&CreateWindowRequest { width, height })
            .map_err(|_| "CreateWindow send failed")?;
        let resp = ctl_ch
            .recv_blocking()
            .map_err(|_| "CreateWindow recv failed")?;
        let req_handle = resp.req_channel.raw();
        let event_handle = resp.event_channel.raw();

        // 3. Typed client + event channel
        let mut client = WindowClient::new(UserTransport::new(req_handle));
        let events = Channel::<Never, WindowEvent>::from_raw_handle(event_handle);

        // 4. GetInfo
        let (w, h, stride) = match client.get_info(1) {
            Ok(WindowReply::InfoReply {
                width,
                height,
                stride,
                ..
            }) => (width, height, stride),
            _ => return Err("GetInfo failed"),
        };

        // 5. GetFramebuffer
        let shm_handle = match client.get_framebuffer(2) {
            Ok(WindowReply::FbReply { fb, .. }) => fb.0,
            _ => return Err("GetFramebuffer failed"),
        };

        // 6. mmap (double-buffered)
        let pixels_per_buffer = (stride as usize) * (h as usize);
        let fb_mapped_size = pixels_per_buffer * 4 * 2;
        let fb_base = raw::mmap(shm_handle, fb_mapped_size)
            .map_err(|_| "mmap failed")? as *mut u32;

        Ok(Window {
            client,
            events,
            req_handle,
            width: w,
            height: h,
            stride,
            fb_base,
            pixels_per_buffer,
            shm_handle,
            fb_mapped_size,
            current_back: 1,
            swap_seq: 10,
        })
    }

    /// Window width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Window height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Stride in pixels (may be wider than width).
    pub fn stride(&self) -> u32 {
        self.stride
    }

    /// Number of pixels in each buffer (stride * height).
    pub fn pixels_per_buffer(&self) -> usize {
        self.pixels_per_buffer
    }

    /// Raw pointer to the current back buffer.
    pub fn back_buffer(&self) -> *mut u32 {
        let offset = if self.current_back == 0 {
            0
        } else {
            self.pixels_per_buffer
        };
        unsafe { self.fb_base.add(offset) }
    }

    /// Current back buffer as a mutable slice.
    pub fn back_buffer_mut(&mut self) -> &mut [u32] {
        unsafe {
            core::slice::from_raw_parts_mut(self.back_buffer(), self.pixels_per_buffer)
        }
    }

    /// Raw pointer to the base of both framebuffers (for apps that need
    /// direct access to both buffers, e.g. persistent drawing).
    pub fn fb_base(&self) -> *mut u32 {
        self.fb_base
    }

    /// Which buffer index is currently the back buffer (0 or 1).
    pub fn current_back(&self) -> u8 {
        self.current_back
    }

    /// Present the back buffer: swap_buffers RPC, toggle, copy front→new back.
    pub fn present(&mut self) {
        let _ = self.client.swap_buffers(self.swap_seq);
        self.swap_seq = self.swap_seq.wrapping_add(1);
        self.current_back = 1 - self.current_back;

        // Copy front → new back so the new back starts with what was just shown
        let front_offset = if self.current_back == 0 {
            self.pixels_per_buffer
        } else {
            0
        };
        let back_offset = if self.current_back == 0 {
            0
        } else {
            self.pixels_per_buffer
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.fb_base.add(front_offset),
                self.fb_base.add(back_offset),
                self.pixels_per_buffer,
            );
        }
    }

    /// Present without copying front→back (for apps that fully redraw each frame).
    pub fn present_no_copy(&mut self) {
        let _ = self.client.swap_buffers(self.swap_seq);
        self.swap_seq = self.swap_seq.wrapping_add(1);
        self.current_back = 1 - self.current_back;
    }

    /// Reference to the event channel for receiving window events.
    pub fn event_channel(&mut self) -> &mut Channel<Never, WindowEvent> {
        &mut self.events
    }

    /// Raw handle for the event channel (for poll_add).
    pub fn event_handle(&self) -> usize {
        self.events.raw_handle()
    }

    /// Raw handle for the request channel (for poll_add).
    pub fn req_handle(&self) -> usize {
        self.req_handle
    }

    /// Mutable access to the underlying WindowClient for direct RPC calls.
    pub fn client(&mut self) -> &mut WindowClient<UserTransport> {
        &mut self.client
    }

    /// Register both the event and request channels for blocking.
    pub fn poll_add(&self) {
        self.events.poll_add();
        raw::sys_chan_poll_add(self.req_handle);
    }

    /// Close the window (sends CloseWindow RPC).
    pub fn close(&mut self) {
        let _ = self.client.close_window();
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.client.close_window();
        // munmap + close SHM
        raw::sys_munmap(self.fb_base as usize, self.fb_mapped_size);
        raw::sys_chan_close(self.shm_handle);
    }
}
