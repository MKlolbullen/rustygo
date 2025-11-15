use libc::c_char;
use std::ffi::{CStr, CString};

#[no_mangle]
pub unsafe extern "C" fn dns_engine_echo(input: *const c_char) -> *mut c_char {
    if input.is_null() {
        return std::ptr::null_mut();
    }

    let cstr = CStr::from_ptr(input);
    let s = match cstr.to_str() {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let out = format!("[dns_engine] {}", s);

    match CString::new(out) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dns_engine_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = CString::from_raw(s);
}
