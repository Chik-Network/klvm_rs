#![no_main]

use klvm_fuzzing::ArbitraryKlvmTree;
use klvmr::serde::is_canonical_serialization;
use klvmr::serde::node_to_bytes_backrefs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|tree: ArbitraryKlvmTree<1000, true>| {
    let buffer = node_to_bytes_backrefs(&tree.allocator, tree.tree)
        .expect("internal error, failed to serialize");
    // out serializer should always produce canonical serialization
    assert!(is_canonical_serialization(&buffer));
});
