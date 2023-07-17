#![no_main]
use libfuzzer_sys::fuzz_target;

use chik_clvmr::allocator::Allocator;
use chik_clvmr::chik_dialect::{
    ChikDialect, ENABLE_BLS_OPS, ENABLE_BLS_OPS_OUTSIDE_GUARD, ENABLE_SECP_OPS, MEMPOOL_MODE,
    NO_UNKNOWN_OPS,
};
use chik_clvmr::cost::Cost;
use chik_clvmr::reduction::Reduction;
use chik_clvmr::run_program::run_program;
use chik_clvmr::serde::node_from_bytes;

fuzz_target!(|data: &[u8]| {
    let mut allocator = Allocator::new();
    let program = match node_from_bytes(&mut allocator, data) {
        Err(_) => {
            return;
        }
        Ok(r) => r,
    };
    let args = allocator.null();

    let allocator_checkpoint = allocator.checkpoint();

    for flags in [
        0,
        ENABLE_BLS_OPS | ENABLE_BLS_OPS_OUTSIDE_GUARD | ENABLE_SECP_OPS,
        ENABLE_BLS_OPS | ENABLE_BLS_OPS_OUTSIDE_GUARD | ENABLE_SECP_OPS | NO_UNKNOWN_OPS,
        MEMPOOL_MODE,
    ] {
        let dialect = ChikDialect::new(flags);
        allocator.restore_checkpoint(&allocator_checkpoint);

        let Reduction(_cost, _node) =
            match run_program(&mut allocator, &dialect, program, args, 11000000000 as Cost) {
                Err(_) => {
                    continue;
                }
                Ok(r) => r,
            };
    }
});
