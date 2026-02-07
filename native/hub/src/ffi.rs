#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    collections::HashMap,
    ffi::{c_char, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};

use prost::Message;

use crate::types;

const MAX_CONFIG_SIZE: usize = 16 * 1024 * 1024;
const MAX_COMMAND_SIZE: usize = 64 * 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 60_000;

static CALL_LOCK: Mutex<()> = Mutex::new(());

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static OUT_BUFFERS: OnceLock<Mutex<HashMap<usize, Vec<u8>>>> = OnceLock::new();

fn out_buffers() -> &'static Mutex<HashMap<usize, Vec<u8>>> {
    OUT_BUFFERS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[repr(C)]
pub struct ByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize, // token id
}

impl ByteBuffer {
    pub fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        if v.is_empty() {
            return Self::empty();
        }

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let ptr = v.as_ptr() as *mut u8;
        let len = v.len();

        let mut map = out_buffers().lock().unwrap_or_else(|p| p.into_inner());
        map.insert(id, v);

        Self { ptr, len, cap: id }
    }
}

#[no_mangle]
pub extern "C" fn hub_free_byte_buffer(buffer: ByteBuffer) {
    if buffer.cap == 0 {
        return;
    }

    let mut map = out_buffers().lock().unwrap_or_else(|p| p.into_inner());
    let _ = map.remove(&buffer.cap);
}

fn encode_init_error(code: &str, message: &str) -> Vec<u8> {
    types::InitializeResponse {
        success: false,
        error_message: format!("[{code}] {message}"),
        node_id: String::new(),
    }
    .encode_to_vec()
}

fn encode_cmd_ok() -> Vec<u8> {
    types::CommandResponse {
        success: true,
        error_message: String::new(),
        data: Vec::new(),
    }
    .encode_to_vec()
}

fn encode_cmd_error(code: &str, message: &str) -> Vec<u8> {
    types::CommandResponse {
        success: false,
        error_message: format!("[{code}] {message}"),
        data: Vec::new(),
    }
    .encode_to_vec()
}

fn copy_in(ptr: *const u8, len: usize, max: usize) -> Result<Vec<u8>, &'static str> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err("null pointer");
    }
    if len > max {
        return Err("input too large");
    }
    unsafe { Ok(slice::from_raw_parts(ptr, len).to_vec()) }
}

#[no_mangle]
pub extern "C" fn ffi_hub_start(config_ptr: *const u8, config_len: usize) -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let out = catch_unwind(AssertUnwindSafe(|| {
        let config = match copy_in(config_ptr, config_len, MAX_CONFIG_SIZE) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return encode_init_error("validation", "Config must not be empty"),
            Err(e) => return encode_init_error("validation", e),
        };
        crate::hub_start(config)
    }))
    .unwrap_or_else(|_| encode_init_error("panic", "hub_start panicked"));

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_stop() -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let out = catch_unwind(AssertUnwindSafe(|| {
        crate::hub_stop();
        encode_cmd_ok()
    }))
    .unwrap_or_else(|_| encode_cmd_error("panic", "hub_stop panicked"));

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_is_initialized() -> bool {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    catch_unwind(AssertUnwindSafe(|| crate::hub_is_initialized())).unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn ffi_hub_send_command(cmd_ptr: *const u8, cmd_len: usize) -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let out = catch_unwind(AssertUnwindSafe(|| {
        let cmd = match copy_in(cmd_ptr, cmd_len, MAX_COMMAND_SIZE) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return encode_cmd_error("validation", "Command must not be empty"),
            Err(e) => return encode_cmd_error("validation", e),
        };
        crate::hub_send_command(cmd)
    }))
    .unwrap_or_else(|_| encode_cmd_error("panic", "hub_send_command panicked"));

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_poll_event(timeout_ms: u64) -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);

    let out = catch_unwind(AssertUnwindSafe(|| crate::hub_poll_event(timeout_ms))).unwrap_or_else(|_| {
        tracing::error!("hub_poll_event panicked");
        Vec::new()
    });

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_destroy() -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let out = catch_unwind(AssertUnwindSafe(|| {
        crate::hub_destroy();
        encode_cmd_ok()
    }))
    .unwrap_or_else(|_| encode_cmd_error("panic", "hub_destroy panicked"));

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_version_bytes() -> ByteBuffer {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let out = catch_unwind(AssertUnwindSafe(|| crate::hub_version().into_bytes()))
        .unwrap_or_else(|_| b"unknown".to_vec());

    ByteBuffer::from_vec(out)
}

#[no_mangle]
pub extern "C" fn ffi_hub_version() -> *mut c_char {
    let _guard = CALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let s = catch_unwind(AssertUnwindSafe(|| crate::hub_version())).unwrap_or_else(|_| "unknown".to_string());
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn ffi_hub_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}