use concolic::{SymExpr, SymExprRef};
use libafl::{
    corpus::Corpus,
    executors::{Executor, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::{HasBytesVec, Input},
    mark_feature_time,
    observers::ObserversTuple,
    stages::{Stage, TracingStage},
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasExecutions, HasMetadata},
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;
use crate::{metadata::ConcolicMetadata, observer::ConcolicObserver};

use z3::ast::{Ast, Bool, Dynamic, BV};
use z3::{Config, Context, Solver, Symbol};

use std::convert::TryInto;
use std::mem::size_of;
use std::{collections::HashMap, marker::PhantomData};

fn generate_mutations(iter: impl Iterator<Item = (SymExprRef, SymExpr)>) -> Vec<Vec<(usize, u8)>> {
    let mut res = Vec::new();

    let ctx = Context::new(&Config::new());
    let solver = Solver::new(&ctx);

    fn build_extract<'ctx>(
        bv: &BV<'ctx>,
        offset: u64,
        length: u64,
        little_endian: bool,
    ) -> BV<'ctx> {
        let size = bv.get_size() as u64;
        assert_eq!(
            size % 8,
            0,
            "can't extract on byte-boundary on BV that is not byte-sized"
        );

        if little_endian {
            let mut result = bv.extract(
                (size as u64 - offset * 8 - 1).try_into().unwrap(),
                (size - offset * 8 - 8).try_into().unwrap(),
            );
            for i in 1..length {
                result = bv
                    .extract(
                        (size - (offset + 1) * 8 - 1).try_into().unwrap(),
                        (size - (offset + i + 1) * 8).try_into().unwrap(),
                    )
                    .concat(&result);
            }
            result
        } else {
            bv.extract(
                (size - offset * 8 - 1).try_into().unwrap(),
                (size - (offset + length) * 8).try_into().unwrap(),
            )
        }
    }

    let mut translation = HashMap::<SymExprRef, Dynamic>::new();
    for (id, msg) in iter {
        let z3_expr: Option<Dynamic> = match msg {
            SymExpr::GetInputByte { offset } => {
                Some(BV::new_const(&ctx, Symbol::Int(offset as u32), 8).into())
            }
            SymExpr::BuildInteger { value, bits } => {
                Some(BV::from_u64(&ctx, value, bits as u32).into())
            }
            SymExpr::BuildInteger128 { high: _, low: _ } => todo!(),
            SymExpr::BuildNullPointer => {
                Some(BV::from_u64(&ctx, 0, (8 * size_of::<usize>()) as u32).into())
            }
            SymExpr::BuildTrue => Some(Bool::from_bool(&ctx, true).into()),
            SymExpr::BuildFalse => Some(Bool::from_bool(&ctx, false).into()),
            SymExpr::BuildBool { value } => Some(Bool::from_bool(&ctx, value).into()),
            SymExpr::BuildNeg { op } => Some(translation[&op].as_bv().unwrap().bvneg().into()),
            SymExpr::BuildAdd { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvadd(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSub { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsub(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildMul { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvmul(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedDiv { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvudiv(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedDiv { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsdiv(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedRem { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvurem(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedRem { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsrem(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildShiftLeft { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvshl(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildLogicalShiftRight { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvlshr(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildArithmeticShiftRight { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvashr(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedLessThan { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvslt(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedLessEqual { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsle(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedGreaterThan { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsgt(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSignedGreaterEqual { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvsge(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedLessThan { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvult(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedLessEqual { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvule(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedGreaterThan { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvugt(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildUnsignedGreaterEqual { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvuge(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
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
            SymExpr::BuildBoolAnd { a, b } => Some(
                Bool::and(
                    &ctx,
                    &[
                        &translation[&a].as_bool().unwrap(),
                        &translation[&b].as_bool().unwrap(),
                    ],
                )
                .into(),
            ),
            SymExpr::BuildBoolOr { a, b } => Some(
                Bool::or(
                    &ctx,
                    &[
                        &translation[&a].as_bool().unwrap(),
                        &translation[&b].as_bool().unwrap(),
                    ],
                )
                .into(),
            ),
            SymExpr::BuildBoolXor { a, b } => Some(
                translation[&a]
                    .as_bool()
                    .unwrap()
                    .xor(&translation[&b].as_bool().unwrap())
                    .into(),
            ),
            SymExpr::BuildAnd { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvand(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildOr { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvor(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildXor { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .bvxor(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::BuildSext { op, bits } => Some(
                translation[&op]
                    .as_bv()
                    .unwrap()
                    .sign_ext(bits as u32)
                    .into(),
            ),
            SymExpr::BuildZext { op, bits } => Some(
                translation[&op]
                    .as_bv()
                    .unwrap()
                    .zero_ext(bits as u32)
                    .into(),
            ),
            SymExpr::BuildTrunc { op, bits } => Some(
                translation[&op]
                    .as_bv()
                    .unwrap()
                    .extract((bits - 1) as u32, 0)
                    .into(),
            ),
            SymExpr::BuildBoolToBits { op, bits } => Some(
                translation[&op]
                    .as_bool()
                    .unwrap()
                    .ite(
                        &BV::from_u64(&ctx, 1, bits as u32),
                        &BV::from_u64(&ctx, 0, bits as u32),
                    )
                    .into(),
            ),
            SymExpr::ConcatHelper { a, b } => Some(
                translation[&a]
                    .as_bv()
                    .unwrap()
                    .concat(&translation[&b].as_bv().unwrap())
                    .into(),
            ),
            SymExpr::ExtractHelper {
                op,
                first_bit,
                last_bit,
            } => Some(
                translation[&op]
                    .as_bv()
                    .unwrap()
                    .extract(first_bit as u32, last_bit as u32)
                    .into(),
            ),
            SymExpr::BuildExtract {
                op,
                offset,
                length,
                little_endian,
            } => {
                let bv = translation[&op].as_bv().unwrap();
                Some(build_extract(&bv, offset, length, little_endian).into())
            }
            SymExpr::BuildBswap { op } => {
                let bv = translation[&op].as_bv().unwrap();
                let bits = bv.get_size();
                assert_eq!(
                    bits % 16,
                    0,
                    "bswap is only compatible with an even number of bvytes in the BV"
                );
                Some(build_extract(&bv, 0, bits as u64 / 8, true).into())
            }
            SymExpr::BuildInsert {
                target,
                to_insert,
                offset,
                little_endian,
            } => {
                let target = translation[&target].as_bv().unwrap();
                let to_insert = translation[&to_insert].as_bv().unwrap();
                let bits_to_insert = to_insert.get_size() as u64;
                assert_eq!(bits_to_insert % 8, 0, "can only insert full bytes");
                let after_len = (target.get_size() as u64 / 8) - offset - (bits_to_insert / 8);
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
                                panic!()
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

/// Wraps a [`TracingStage`] to add concolic observing.
#[derive(Clone, Debug)]
pub struct ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<OT> + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    inner: TracingStage<C, EM, I, OT, S, TE, Z>,
    observer_name: String,
}

impl<E, C, EM, I, OT, S, TE, Z> Stage<E, EM, S, Z> for ConcolicTracingStage<C, EM, I, OT, S, TE, Z>
where
    I: Input,
    C: Corpus<I>,
    TE: Executor<EM, I, S, Z> + HasObservers<OT> + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
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
    TE: Executor<EM, I, S, Z> + HasObservers<OT> + HasObserversHooks<EM, I, OT, S, Z>,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    /// Creates a new default mutational stage
    pub fn new(inner: TracingStage<C, EM, I, OT, S, TE, Z>, observer_name: String) -> Self {
        Self {
            inner,
            observer_name,
        }
    }
}

/// Wraps a [`TracingStage`] to add concolic observing.
#[derive(Clone, Debug)]
pub struct ConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    inner: PhantomData<(C, EM, I, S, Z)>,
}

impl<E, C, EM, I, S, Z> Stage<E, EM, S, Z> for ConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input + HasBytesVec,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
    Z: libafl::Evaluator<E, EM, I, S>,
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
        let testcase = state.corpus().get(corpus_idx)?;
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

impl<C, EM, I, S, Z> ConcolicMutationalStage<C, EM, I, S, Z>
where
    I: Input,
    C: Corpus<I>,
    S: HasClientPerfStats + HasExecutions + HasCorpus<C, I>,
{
    /// Creates a new default mutational stage
    pub fn new() -> Self {
        Self { inner: PhantomData }
    }
}
