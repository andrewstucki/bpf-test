use std::{thread, time};

use probe_sys::{State, SleepEvent};

fn main() {
    let probe = State::new(|e: SleepEvent| {
        println!("Got a sleep! {:?}", e);
    }).unwrap();

    thread::sleep(time::Duration::from_millis(10));
    thread::sleep(time::Duration::from_millis(10));
    thread::sleep(time::Duration::from_millis(10));
    thread::sleep(time::Duration::from_millis(10));
    thread::sleep(time::Duration::from_millis(10));
    thread::sleep(time::Duration::from_millis(10));
    
    probe.poll(100);
}
