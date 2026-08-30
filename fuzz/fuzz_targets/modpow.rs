#![no_main]

use klvm_fuzzing::build_args;
use klvmr::allocator::{Allocator, NodePtr};
use klvmr::chik_dialect::KlvmFlags;
use klvmr::cost::Cost;
use klvmr::error::EvalErr;
use klvmr::more_ops::op_modpow;
use klvmr::number::Number;
use klvmr::reduction::Response;
use libfuzzer_sys::fuzz_target;
use num_bigint::Sign;

const MAX_COST: Cost = 6_000_000_000;

type Opf = fn(&mut Allocator, NodePtr, Cost, KlvmFlags) -> Response;

fn check_modpow(
    op: Opf,
    base: &Number,
    exp: &Number,
    modulus: &Number,
    name: &str,
    flags: KlvmFlags,
) {
    let mut alloc = Allocator::new();
    let args = build_args(&mut alloc, &[base, exp, modulus]);
    let klvm_result = op(&mut alloc, args, MAX_COST, flags);

    // num-bigint panics on zero modulus or negative exponent, and
    // cargo-fuzz compiles with panic=abort so catch_unwind cannot
    // intercept those panics. Check preconditions explicitly instead.
    let invalid_input = modulus.sign() == Sign::NoSign || exp.sign() == Sign::Minus;

    match klvm_result {
        Err(EvalErr::CostExceeded) => {}
        Err(EvalErr::InvalidOpArg(_, _)) => {}
        Err(_) => {
            assert!(
                invalid_input,
                "{name}({base}, {exp}, {modulus}): KLVM failed but inputs are valid"
            );
        }
        Ok(reduction) => {
            assert!(
                !invalid_input,
                "{name}({base}, {exp}, {modulus}): KLVM succeeded but inputs are invalid"
            );
            let expected = base.modpow(exp, modulus);
            assert_eq!(
                alloc.number(reduction.1),
                expected,
                "{name}({base}, {exp}, {modulus}): result mismatch"
            );
        }
    }
}

fuzz_target!(|input: (Vec<u8>, Vec<u8>, Vec<u8>)| {
    let base = Number::from_signed_bytes_be(&input.0);
    let exp = Number::from_signed_bytes_be(&input.1);
    let modulus = Number::from_signed_bytes_be(&input.2);

    for flags in [KlvmFlags::empty(), KlvmFlags::MALACHITE] {
        check_modpow(op_modpow, &base, &exp, &modulus, "modpow", flags);
    }
});
