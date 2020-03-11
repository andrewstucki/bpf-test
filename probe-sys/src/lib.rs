#![allow(non_camel_case_types)]

use std::panic;
use std::fmt;
use std::os::raw::c_int;

pub mod ffi {
    use std::os::raw::{c_int, c_void};

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct event {
        pub tid: u32,
        pub pid: u32,
        pub gid: u32,
        pub uid: u32,
        pub cpu: u32,
    }
    pub type event_handler = extern "C" fn(ctx: *mut c_void, e: event);
    pub enum state {}
    extern "C" {
        pub fn new_state(ctx: *mut c_void, handler: event_handler) -> *mut state;
        pub fn poll_state(_self: *mut state, timeout: c_int);
        pub fn destroy_state(_self: *mut state);
    }

    /// Unpack a Rust closure, extracting a `void*` pointer to the data and a
    /// trampoline function which can be used to invoke it.
    ///
    /// # Safety
    ///
    /// It is the user's responsibility to ensure the closure outlives the returned
    /// `void*` pointer.
    ///
    /// Calling the trampoline function with anything except the `void*` pointer
    /// will result in *Undefined Behaviour*.
    ///
    /// The closure should guarantee that it never panics, seeing as panicking 
    /// across the FFI barrier is *Undefined Behaviour*. You may find 
    /// `std::panic::catch_unwind()` useful.
    pub unsafe fn unpack_closure<F>(closure: &mut F) -> (*mut c_void, event_handler)
    where
        F: FnMut(event),
    {
        extern "C" fn trampoline<F>(data: *mut c_void, e: event)
        where
            F: FnMut(event),
        {
            let closure: &mut F = unsafe { &mut *(data as *mut F) };
            (*closure)(e);
        }

        (closure as *mut F as *mut c_void, trampoline::<F>)
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    InitializationError
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InitializationError => f.write_str("Could not initialize BPF object, ensure you're using Linux kernel >= 4.18"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub tid: u32,
    pub pid: u32,
    pub gid: u32,
    pub uid: u32,
    pub cpu: u32,
}

pub struct State<'a> {
    ctx: *mut ffi::state,
    // store the closure so that we make sure it has
    // the same lifetime as the state wrapper
    _handler: Box<dyn 'a + Fn(ffi::event)>,
}

impl<'a> State<'a> {
    pub fn new<F: 'a>(handler: F) -> Result<Self, Error>
        where F: 'a + Fn(Event) + panic::RefUnwindSafe {
        let mut wrapper = move |e: ffi::event| {
            let result = panic::catch_unwind(|| {
                handler(Event{
                    tid: e.tid, 
                    pid: e.pid,
                    gid: e.gid, 
                    uid: e.uid, 
                    cpu: e.cpu,
                });
            });
            // do something with the panic
            result.unwrap();
        };
        let (closure, callback) = unsafe { ffi::unpack_closure(&mut wrapper) };
        let state = unsafe { ffi::new_state(closure, callback) };
        if state.is_null() {
            return Err(Error::InitializationError)
        }
        Ok(State { ctx: state, _handler: Box::new(wrapper) })
    }

    pub fn poll(&self, timeout: i32) {
        unsafe { ffi::poll_state(self.ctx, timeout as c_int) }
    }
}

impl <'a>Drop for State<'a> {
    fn drop(&mut self) {
        unsafe { ffi::destroy_state(self.ctx) }
    }
}
