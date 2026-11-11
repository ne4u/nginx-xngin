// Rust codec fuzz target. Setup (one time):
//   cargo install cargo-fuzz
//   cargo fuzz init --fuzz-target-name fuzz_codec
// then drop this file in as fuzz/fuzz_targets/fuzz_codec.rs and run:
//   cargo fuzz run fuzz_codec
#![no_main]

use libfuzzer_sys::fuzz_target;
use xngin_rs::proto::*;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    if let Ok(frames) = feed(&mut buf) {
        for fr in frames {
            let _ = fr.kvs();
            let _ = fr.notify();
            let _ = fr.marshal(); // must never panic
        }
    }
});
