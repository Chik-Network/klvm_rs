#![no_main]
mod make_tree;

use klvmr::serde::is_canonical_serialization;
use klvmr::serde::node_to_bytes;
use klvmr::Allocator;
use libfuzzer_sys::fuzz_target;
use make_tree::make_tree_limits;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut a = Allocator::new();
    let (tree, _) = make_tree_limits(&mut a, &mut unstructured, 1000, false);

    let buffer = node_to_bytes(&a, tree).expect("internal error, failed to serialize");

    // out serializer should always produce canonical serialization
    assert!(is_canonical_serialization(&buffer));
});
