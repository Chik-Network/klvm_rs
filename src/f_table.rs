use super::core_ops::{op_cons, op_eq, op_first, op_if, op_listp, op_raise, op_rest};
use super::more_ops::{op_add, op_gr, op_multiply, op_sha256, op_sha256_tree, op_subtract};
use super::types::OpFn;

pub type FLookup = [Option<OpFn>; 256];

static OPCODE_LOOKUP: [(u8, OpFn); 13] = [
    (4, op_if),
    (5, op_cons),
    (6, op_first),
    (7, op_rest),
    (8, op_listp),
    (9, op_raise),
    (10, op_eq),
    (11, op_sha256),
    (12, op_add),
    (13, op_subtract),
    (14, op_multiply),
    (21, op_sha256_tree),
    (22, op_gr),
];

pub fn make_f_lookup() -> FLookup {
    let mut f_lookup: FLookup = [None; 256];
    for (op, f) in &OPCODE_LOOKUP {
        f_lookup[*op as usize] = Some(*f);
    }

    f_lookup
}