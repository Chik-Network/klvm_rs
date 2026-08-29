use crate::allocator::{Allocator, NodePtr};
use crate::chik_dialect::KlvmFlags;
use crate::cost::Cost;
use crate::dialect::{Dialect, OperatorSet};
use crate::error::EvalErr;
use crate::f_table::{FLookup, f_lookup_for_hashmap};
use crate::more_ops::op_unknown;
use crate::reduction::Response;
use std::collections::HashMap;

pub struct RuntimeDialect {
    f_lookup: FLookup,
    quote_kw: Vec<u8>,
    apply_kw: Vec<u8>,
    softfork_kw: Vec<u8>,
    flags: KlvmFlags,
}

impl RuntimeDialect {
    pub fn new(
        op_map: HashMap<String, Vec<u8>>,
        quote_kw: Vec<u8>,
        apply_kw: Vec<u8>,
        flags: KlvmFlags,
    ) -> RuntimeDialect {
        RuntimeDialect {
            f_lookup: f_lookup_for_hashmap(op_map),
            quote_kw,
            apply_kw,
            softfork_kw: vec![36], // softfork opcode
            flags,
        }
    }
}

impl Dialect for RuntimeDialect {
    fn gc_candidate(&self, _allocator: &Allocator, _op: NodePtr) -> bool {
        false
    }
    fn op(
        &self,
        allocator: &mut Allocator,
        o: NodePtr,
        argument_list: NodePtr,
        max_cost: Cost,
        _extensions: OperatorSet,
    ) -> Response {
        let atom = allocator.atom(o);
        let b = atom.as_ref();

        if b.len() == 1
            && let Some(f) = self.f_lookup[b[0] as usize]
        {
            return f(allocator, argument_list, max_cost, self.flags);
        }
        if self.flags.contains(KlvmFlags::NO_UNKNOWN_OPS) {
            Err(EvalErr::Unimplemented(o))?
        } else {
            op_unknown(allocator, o, argument_list, max_cost)
        }
    }

    fn quote_kw(&self) -> u32 {
        self.quote_kw[0] as u32
    }
    fn apply_kw(&self) -> u32 {
        self.apply_kw[0] as u32
    }
    fn softfork_kw(&self) -> u32 {
        self.softfork_kw[0] as u32
    }

    fn softfork_extension(&self, _ext: u32) -> OperatorSet {
        OperatorSet::Default
    }

    fn allow_unknown_ops(&self) -> bool {
        !self.flags.contains(KlvmFlags::NO_UNKNOWN_OPS)
    }

    fn flags(&self) -> KlvmFlags {
        self.flags
    }
}
