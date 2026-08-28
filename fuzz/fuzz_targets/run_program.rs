#![no_main]

use klvm_fuzzing::{make_klvm_program, make_tree_limits};
use libfuzzer_sys::{Corpus, fuzz_target};

use klvmr::allocator::Allocator;
use klvmr::chik_dialect::{ChikDialect, KlvmFlags, MEMPOOL_MODE};
use klvmr::cost::Cost;
use klvmr::error::EvalErr;
use klvmr::reduction::Reduction;
use klvmr::run_program::run_program;

fuzz_target!(|data: &[u8]| -> Corpus {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut allocator = Allocator::new();
    let (args, _) =
        make_tree_limits(&mut allocator, &mut unstructured, 100, true).expect("out of memory");
    let Ok(program) = make_klvm_program(&mut allocator, &mut unstructured, args, 100_000) else {
        return Corpus::Reject;
    };

    let allocator_checkpoint = allocator.checkpoint();

    for flags in [
        KlvmFlags::empty(),
        KlvmFlags::NO_UNKNOWN_OPS,
        MEMPOOL_MODE,
        KlvmFlags::LIMITS,
    ] {
        let dialect = ChikDialect::new(flags.union(KlvmFlags::DISABLE_OP));
        allocator.restore_checkpoint(&allocator_checkpoint);

        let result = run_program(
            &mut allocator,
            &dialect,
            program,
            args,
            11_000_000_000 as Cost,
        );

        match &result {
            Ok(Reduction(cost, _node)) => assert!(*cost < 11_000_000_000),
            Err(EvalErr::InternalError(..)) => {
                panic!("run_program returned InternalError: {:?}", result)
            }
            Err(_) => {}
        }
    }
    Corpus::Keep
});
