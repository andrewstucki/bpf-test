use probe_sys::{State, Event};

fn main() {
    match State::new(|e: Event| {
        println!("Got an event! {:?}", e);
    }) {
        Ok(probe) => { probe.poll(10000); },
        Err(error) => { println!("{}", error); }
    }
}
