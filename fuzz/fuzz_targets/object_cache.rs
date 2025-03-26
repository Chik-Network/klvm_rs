#![no_main]
mod fuzzing_utils;
mod make_tree;
mod pick_node;
mod serialized_len;

use fuzzing_utils::tree_hash;
use klvmr::serde::{serialized_length, treehash, ObjectCache};
use klvmr::Allocator;
use libfuzzer_sys::fuzz_target;
use serialized_len::compute_serialized_len;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = arbitrary::Unstructured::new(data);
    let mut allocator = Allocator::new();
    let (tree, node_count) =
        make_tree::make_tree_limits(&mut allocator, &mut unstructured, 10_000, true);

    let mut hash_cache = ObjectCache::new(treehash);
    let mut length_cache = ObjectCache::new(serialized_length);

    let node_idx = unstructured.int_in_range(0..=node_count).unwrap_or(5) as i32;
    let node = pick_node::pick_node(&allocator, tree, node_idx);

    let expect_hash = tree_hash(&allocator, node);
    let expect_len = compute_serialized_len(&allocator, node);
    let computed_hash = hash_cache
        .get_or_calculate(&allocator, &node, None)
        .unwrap();
    let computed_len = length_cache
        .get_or_calculate(&allocator, &node, None)
        .unwrap();
    assert_eq!(computed_hash, &expect_hash);
    assert_eq!(computed_len, &expect_len);
});
