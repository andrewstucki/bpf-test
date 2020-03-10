#![allow(non_camel_case_types)]

use std::fmt;
use std::error::Error as StdError;


pub mod ffi {
    pub enum state {}
    extern "C" {
        pub fn new_state() -> *mut state;
        pub fn poll_state(_self: *mut state, timeout: std::os::raw::c_int);
        pub fn destroy_state(_self: *mut state);
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InitializationError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InitializationError => f.write_str("InitializationError"),
        }
    }
}
impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InitializationError => "Initialization error: could not initialize bpf probe",
        }
    }
}

pub struct State {
    ctx: *mut ffi::state,
}

impl State {
    pub fn new() -> Result<Self, Error> {
        let state = unsafe { ffi::new_state() };
        if state.is_null() {
            return Err(Error::InitializationError)
        }
        Ok(State { ctx: state })
    }

    pub fn poll(&self, timeout: i32) {
        unsafe { ffi::poll_state(self.ctx, timeout as std::os::raw::c_int) }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        unsafe { ffi::destroy_state(self.ctx) }
    }
}
