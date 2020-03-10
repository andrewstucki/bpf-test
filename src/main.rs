use probe_sys;

fn main() {
    let probe = probe_sys::State::new().unwrap();
    probe.poll(100);
}
