#![no_main]

mod make_tree;
mod node_eq;

use klvmr::allocator::Allocator;
use klvmr::serde::{
    node_from_bytes_backrefs, node_from_bytes_backrefs_old, node_to_bytes_backrefs,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut allocator = Allocator::new();
    let mut unstructured = arbitrary::Unstructured::new(data);

    let (program, _) = make_tree::make_tree(&mut allocator, &mut unstructured);

    let b1 = node_to_bytes_backrefs(&allocator, program).unwrap();

    let mut allocator = Allocator::new();
    let program = node_from_bytes_backrefs(&mut allocator, &b1).expect("node_from_bytes_backrefs");
    let node_count = allocator.pair_count();

    let program_old =
        node_from_bytes_backrefs_old(&mut allocator, &b1).expect("node_from_bytes_backrefs_old");
    // check that the new implementation creates the same number of pair nodes as the old one
    assert_eq!(node_count * 2, allocator.pair_count());
    assert!(node_eq::node_eq(&allocator, program, program_old));

    let b2 = node_to_bytes_backrefs(&allocator, program).expect("node_to_bytes_backrefs");
    if b1 != b2 {
        panic!("b1 and b2 do not match");
    }
});
