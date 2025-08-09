#![no_main]

use klvm_fuzzing::make_tree_limits;
use libfuzzer_sys::fuzz_target;

use klvmr::allocator::Allocator;
use klvmr::chik_dialect::{ChikDialect, MEMPOOL_MODE, NO_UNKNOWN_OPS};
use klvmr::cost::Cost;
use klvmr::reduction::Reduction;
use klvmr::run_program::run_program;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut allocator = Allocator::new();
    let (program, _) =
        make_tree_limits(&mut allocator, &mut unstructured, 10_000, true).expect("out of memory");
    let (args, _) =
        make_tree_limits(&mut allocator, &mut unstructured, 10_000, true).expect("out of memory");

    let allocator_checkpoint = allocator.checkpoint();

    for flags in [0, NO_UNKNOWN_OPS, MEMPOOL_MODE] {
        let dialect = ChikDialect::new(flags);
        allocator.restore_checkpoint(&allocator_checkpoint);

        let Ok(Reduction(cost, _node)) = run_program(
            &mut allocator,
            &dialect,
            program,
            args,
            11_000_000_000 as Cost,
        ) else {
            continue;
        };
        assert!(cost < 11_000_000_000);
    }
});
