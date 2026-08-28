use klvmr::allocator::{Allocator, NodePtr};
use klvmr::number::Number;

pub fn build_args(a: &mut Allocator, vals: &[&Number]) -> NodePtr {
    let mut args = a.nil();
    for v in vals.iter().rev() {
        let node = a.new_number((*v).clone()).unwrap();
        args = a.new_pair(node, args).unwrap();
    }
    args
}
