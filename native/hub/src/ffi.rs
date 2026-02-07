use std::ffi::{c_char, CStr, CString};
use std::slice;

#[repr(C)]
pub struct ByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl ByteBuffer {
    pub fn new(vec: Vec<u8>) -> Self {
        let mut v = std::mem::ManuallyDrop::new(vec);
        Self {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        }
    }

    pub fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Frees a ByteBuffer returned by Rust
#[no_mangle]
pub extern "C" fn hub_free_byte_buffer(buffer: ByteBuffer) {
    if !buffer.ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap);
        }
    }
}

/// Start the hub
#[no_mangle]
pub unsafe extern "C" fn ffi_hub_start(config_ptr: *const u8, config_len: usize) -> ByteBuffer {
    let config = slice::from_raw_parts(config_ptr, config_len).to_vec();
    let result = crate::hub_start(config);
    ByteBuffer::new(result)
}

/// Stop the hub
#[no_mangle]
pub extern "C" fn ffi_hub_stop() -> ByteBuffer {
    let result = crate::hub_stop();
    ByteBuffer::new(result)
}

/// Check if initialized
#[no_mangle]
pub extern "C" fn ffi_hub_is_initialized() -> bool {
    crate::hub_is_initialized()
}

/// Send command
#[no_mangle]
pub unsafe extern "C" fn ffi_hub_send_command(cmd_ptr: *const u8, cmd_len: usize) -> ByteBuffer {
    let cmd = slice::from_raw_parts(cmd_ptr, cmd_len).to_vec();
    let result = crate::hub_send_command(cmd);
    ByteBuffer::new(result)
}

/// Poll event
#[no_mangle]
pub extern "C" fn ffi_hub_poll_event(timeout_ms: u64) -> ByteBuffer {
    let result = crate::hub_poll_event(timeout_ms);
    ByteBuffer::new(result)
}

/// Destroy hub resources
#[no_mangle]
pub extern "C" fn ffi_hub_destroy() -> ByteBuffer {
    let result = crate::hub_destroy();
    ByteBuffer::new(result)
}

/// Get version
#[no_mangle]
pub extern "C" fn ffi_hub_version() -> *mut c_char {
    let v = crate::hub_version();
    CString::new(v).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn ffi_hub_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}
