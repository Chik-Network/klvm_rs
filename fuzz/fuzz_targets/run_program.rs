#![no_main]
use libfuzzer_sys::fuzz_target;

use klvmr::allocator::Allocator;
use klvmr::chik_dialect::ChikDialect;
use klvmr::cost::Cost;
use klvmr::reduction::Reduction;
use klvmr::run_program::run_program;
use klvmr::serialize::node_from_bytes;

fuzz_target!(|data: &[u8]| {
    let mut allocator = Allocator::new();
    let program = match node_from_bytes(&mut allocator, data) {
        Err(_) => {
            return;
        }
        Ok(r) => r,
    };
    let args = allocator.null();
    let dialect = ChikDialect::new(0);

    let Reduction(_cost, _node) = match run_program(
        &mut allocator,
        &dialect,
        program,
        args,
        12000000000 as Cost,
        None,
    ) {
        Err(_) => {
            return;
        }
        Ok(r) => r,
    };
});
