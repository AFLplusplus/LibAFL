use core::marker::PhantomData;

use crate::{
    corpus::Corpus,
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::{concolic::ConcolicObserver, ObserversTuple},
    state::{HasClientPerfStats, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

use super::{Stage, TracingStage};

/// Wraps a [`TracingStage`] to add concolic observing.
#[derive(Clone, Debug)]
pub struct ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    inner: TracingStage<C, EM, I, OT, S, TE, Z>,
    observer_name: String,
}

impl<E, C, EM, I, OT, S, TE, Z> Stage<E, EM, S, Z> for ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.inner
            .perform(fuzzer, executor, state, manager, corpus_idx)?;
        if let Some(observer) = self
            .inner
            .executor()
            .observers()
            .match_name::<ConcolicObserver>(&self.observer_name)
        {
            let metadata = observer.create_metadata_from_current_map();
            state
                .corpus_mut()
                .get(corpus_idx)
                .unwrap()
                .borrow_mut()
                .metadata_mut()
                .insert(metadata);
        }
        Ok(())
    }
}

impl<C, EM, I, OT, S, TE, Z> ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    /// Creates a new default tracing stage using the given [`Executor`], observing traces from a [`ConcolicObserver`] with the given name.
    pub fn new(inner: TracingStage<C, EM, I, OT, S, TE, Z>, observer_name: String) -> Self {
        Self {
            inner,
            observer_name,
        }
    }
}

#[cfg(feature = "concolic_mutation")]
use crate::{
    inputs::HasBytesVec,
    mark_feature_time,
    observers::concolic::{ConcolicMetadata, SymExpr, SymExprRef},
    start_timer, Evaluator,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;

#[cfg(feature = "concolic_mutation")]
#[allow(clippy::too_many_lines)]
fn generate_mutations(iter: impl Iterator<Item = (SymExprRef, SymExpr)>) -> Vec<Vec<(usize, u8)>> {
    use core::mem::size_of;
    use hashbrown::HashMap;
    use std::convert::TryInto;
    use z3::{
        ast::{Ast, Bool, Dynamic, BV},
        Config, Context, Solver, Symbol,
    };
    fn build_extract<'ctx>(
        bv: &BV<'ctx>,
        offset: u64,
        length: u64,
        little_endian: bool,
    ) -> BV<'ctx> {
        let size = u64::from(bv.get_size());
        assert_eq!(
            size % 8,
            0,
            "can't extract on byte-boundary on BV that is not byte-sized"
        );

        if little_endian {
            (0..length)
                .map(|i| {
                    bv.extract(
                        (size - (offset + i) * 8 - 1).try_into().unwrap(),
                        (size - (offset + i + 1) * 8).try_into().unwrap(),
                    )
                })
                .reduce(|acc, next| next.concat(&acc))
                .unwrap()
        } else {
            bv.extract(
                (size - offset * 8 - 1).try_into().unwrap(),
                (size - (offset + length) * 8).try_into().unwrap(),
            )
        }
    }

    let mut res = Vec::new();

    let ctx = Context::new(&Config::new());
    let solver = Solver::new(&ctx);

    let mut translation = HashMap::<SymExprRef, Dynamic>::new();

    macro_rules! bool {
        ($op:ident) => {
            translation[&$op].as_bool().unwrap()
        };
    }

    macro_rules! bv {
        ($op:ident) => {
            translation[&$op].as_bv().unwrap()
        };
    }

    macro_rules! bv_binop {
        ($a:ident $op:tt $b:ident) => {
            Some(bv!($a).$op(&bv!($b)).into())
        };
    }

    for (id, msg) in iter {
        let z3_expr: Option<Dynamic> = match msg {
            SymExpr::GetInputByte { offset } => {
                Some(BV::new_const(&ctx, Symbol::Int(offset as u32), 8).into())
            }
            SymExpr::BuildInteger { value, bits } => {
                Some(BV::from_u64(&ctx, value, u32::from(bits)).into())
            }
            SymExpr::BuildInteger128 { high: _, low: _ } => todo!(),
            SymExpr::BuildNullPointer => {
                Some(BV::from_u64(&ctx, 0, (8 * size_of::<usize>()) as u32).into())
            }
            SymExpr::BuildTrue => Some(Bool::from_bool(&ctx, true).into()),
            SymExpr::BuildFalse => Some(Bool::from_bool(&ctx, false).into()),
            SymExpr::BuildBool { value } => Some(Bool::from_bool(&ctx, value).into()),
            SymExpr::BuildNeg { op } => Some(bv!(op).bvneg().into()),
            SymExpr::BuildAdd { a, b } => bv_binop!(a bvadd b),
            SymExpr::BuildSub { a, b } => bv_binop!(a bvsub b),
            SymExpr::BuildMul { a, b } => bv_binop!(a bvmul b),
            SymExpr::BuildUnsignedDiv { a, b } => bv_binop!(a bvudiv b),
            SymExpr::BuildSignedDiv { a, b } => bv_binop!(a bvsdiv b),
            SymExpr::BuildUnsignedRem { a, b } => bv_binop!(a bvurem b),
            SymExpr::BuildSignedRem { a, b } => bv_binop!(a bvsrem b),
            SymExpr::BuildShiftLeft { a, b } => bv_binop!(a bvshl b),
            SymExpr::BuildLogicalShiftRight { a, b } => bv_binop!(a bvlshr b),
            SymExpr::BuildArithmeticShiftRight { a, b } => bv_binop!(a bvashr b),
            SymExpr::BuildSignedLessThan { a, b } => bv_binop!(a bvslt b),
            SymExpr::BuildSignedLessEqual { a, b } => bv_binop!(a bvsle b),
            SymExpr::BuildSignedGreaterThan { a, b } => bv_binop!(a bvsgt b),
            SymExpr::BuildSignedGreaterEqual { a, b } => bv_binop!(a bvsge b),
            SymExpr::BuildUnsignedLessThan { a, b } => bv_binop!(a bvult b),
            SymExpr::BuildUnsignedLessEqual { a, b } => bv_binop!(a bvule b),
            SymExpr::BuildUnsignedGreaterThan { a, b } => bv_binop!(a bvugt b),
            SymExpr::BuildUnsignedGreaterEqual { a, b } => bv_binop!(a bvuge b),
            SymExpr::BuildNot { op } => {
                let translated = &translation[&op];
                Some(if let Some(bv) = translated.as_bv() {
                    bv.bvnot().into()
                } else if let Some(bool) = translated.as_bool() {
                    bool.not().into()
                } else {
                    panic!(
                        "unexpected z3 expr of type {:?} when applying not operation",
                        translated.kind()
                    )
                })
            }
            SymExpr::BuildEqual { a, b } => Some(translation[&a]._eq(&translation[&b]).into()),
            SymExpr::BuildNotEqual { a, b } => {
                Some(translation[&a]._eq(&translation[&b]).not().into())
            }
            SymExpr::BuildBoolAnd { a, b } => Some(Bool::and(&ctx, &[&bool!(a), &bool!(b)]).into()),
            SymExpr::BuildBoolOr { a, b } => Some(Bool::or(&ctx, &[&bool!(a), &bool!(b)]).into()),
            SymExpr::BuildBoolXor { a, b } => Some(bool!(a).xor(&bool!(b)).into()),
            SymExpr::BuildAnd { a, b } => bv_binop!(a bvand b),
            SymExpr::BuildOr { a, b } => bv_binop!(a bvor b),
            SymExpr::BuildXor { a, b } => bv_binop!(a bvxor b),
            SymExpr::BuildSext { op, bits } => Some(bv!(op).sign_ext(u32::from(bits)).into()),
            SymExpr::BuildZext { op, bits } => Some(bv!(op).zero_ext(u32::from(bits)).into()),
            SymExpr::BuildTrunc { op, bits } => {
                Some(bv!(op).extract(u32::from(bits - 1), 0).into())
            }
            SymExpr::BuildBoolToBits { op, bits } => Some(
                bool!(op)
                    .ite(
                        &BV::from_u64(&ctx, 1, u32::from(bits)),
                        &BV::from_u64(&ctx, 0, u32::from(bits)),
                    )
                    .into(),
            ),
            SymExpr::ConcatHelper { a, b } => bv_binop!(a concat b),
            SymExpr::ExtractHelper {
                op,
                first_bit,
                last_bit,
            } => Some(bv!(op).extract(first_bit as u32, last_bit as u32).into()),
            SymExpr::BuildExtract {
                op,
                offset,
                length,
                little_endian,
            } => Some(build_extract(&(bv!(op)), offset, length, little_endian).into()),
            SymExpr::BuildBswap { op } => {
                let bv = bv!(op);
                let bits = bv.get_size();
                assert_eq!(
                    bits % 16,
                    0,
                    "bswap is only compatible with an even number of bvytes in the BV"
                );
                Some(build_extract(&bv, 0, u64::from(bits) / 8, true).into())
            }
            SymExpr::BuildInsert {
                target,
                to_insert,
                offset,
                little_endian,
            } => {
                let target = bv!(target);
                let to_insert = bv!(to_insert);
                let bits_to_insert = u64::from(to_insert.get_size());
                assert_eq!(bits_to_insert % 8, 0, "can only insert full bytes");
                let after_len = (u64::from(target.get_size()) / 8) - offset - (bits_to_insert / 8);
                Some(
                    std::array::IntoIter::new([
                        if offset == 0 {
                            None
                        } else {
                            Some(build_extract(&target, 0, offset, false))
                        },
                        Some(if little_endian {
                            build_extract(&to_insert, 0, bits_to_insert / 8, true)
                        } else {
                            to_insert
                        }),
                        if after_len == 0 {
                            None
                        } else {
                            Some(build_extract(
                                &target,
                                offset + (bits_to_insert / 8),
                                after_len,
                                false,
                            ))
                        },
                    ])
                    .reduce(|acc: Option<BV>, val: Option<BV>| match (acc, val) {
                        (Some(prev), Some(next)) => Some(prev.concat(&next)),
                        (Some(prev), None) => Some(prev),
                        (None, next) => next,
                    })
                    .unwrap()
                    .unwrap()
                    .into(),
                )
            }
            _ => None,
        };
        if let Some(expr) = z3_expr {
            translation.insert(id, expr);
        } else if let SymExpr::PushPathConstraint {
            constraint,
            site_id: _,
            taken,
        } = msg
        {
            let op = translation[&constraint].as_bool().unwrap();
            let op = if taken { op } else { op.not() }.simplify();
            if op.as_bool().is_some() {
                // this constraint is useless, as it is always sat or unsat
            } else {
                let negated_constraint = op.not().simplify();
                solver.push();
                solver.assert(&negated_constraint);
                match solver.check() {
                    z3::SatResult::Unsat => {
                        // negation is unsat => no mutation
                        solver.pop(1);
                        // check that out path is ever still sat, otherwise, we can stop trying
                        if matches!(
                            solver.check(),
                            z3::SatResult::Unknown | z3::SatResult::Unsat
                        ) {
                            return res;
                        }
                    }
                    z3::SatResult::Unknown => {
                        // we've got a problem. ignore
                        solver.pop(1);
                    }
                    z3::SatResult::Sat => {
                        let model = solver.get_model().unwrap();
                        let model_string = model.to_string();
                        let mut replacements = Vec::new();
                        for l in model_string.lines() {
                            if let [offset_str, value_str] =
                                l.split(" -> ").collect::<Vec<_>>().as_slice()
                            {
                                let offset = offset_str
                                    .trim_start_matches("k!")
                                    .parse::<usize>()
                                    .unwrap();
                                let value =
                                    u8::from_str_radix(value_str.trim_start_matches("#x"), 16)
                                        .unwrap();
                                replacements.push((offset, value));
                            } else {
                                panic!();
                            }
                        }
                        res.push(replacements);
                        solver.pop(1);
                    }
                };
                // assert the path constraint
                solver.assert(&op);
            }
        }
    }

    res
}

/// A mutational stage that uses Z3 to solve concolic constraints attached to the [`Testcase`] by the [`ConcolicTracingStage`].
#[derive(Clone, Debug)]
pub struct SimpleConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    _phantom: PhantomData<(C, EM, I, S, Z)>,
}

#[cfg(feature = "concolic_mutation")]
impl<E, C, EM, I, S, Z> Stage<E, EM, S, Z> for SimpleConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input + HasBytesVec,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        start_timer!(state);
        let testcase = state.corpus().get(corpus_idx)?.clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let mutations = if let Some(meta) = testcase.borrow().metadata().get::<ConcolicMetadata>() {
            start_timer!(state);
            let mutations = generate_mutations(meta.iter_messages());
            mark_feature_time!(state, PerfFeature::Mutate);
            Some(mutations)
        } else {
            None
        };

        if let Some(mutations) = mutations {
            let input = { testcase.borrow().input().as_ref().unwrap().clone() };
            for mutation in mutations {
                let mut input_copy = input.to_owned();
                for (index, new_byte) in mutation {
                    input_copy.bytes_mut()[index] = new_byte;
                }
                // Time is measured directly the `evaluate_input` function
                let _ = fuzzer.evaluate_input(state, executor, manager, input_copy)?;
            }
        }
        Ok(())
    }
}

impl<C, EM, I, S, Z> Default for SimpleConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}
