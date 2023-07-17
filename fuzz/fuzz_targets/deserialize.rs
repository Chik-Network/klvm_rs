#![no_main]
use chik_clvmr::allocator::Allocator;
use chik_clvmr::serde::node_from_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut allocator = Allocator::new();
    let _program = match node_from_bytes(&mut allocator, data) {
        Err(_) => {
            return;
        }
        Ok(r) => r,
    };
});
