//! While normal stages call the executor over and over again, push stages turn this concept upside down:
//! A push stage instead returns an iterator that generates a new result for each time it gets called.
//! With the new testcase, you will have to take care about testcase execution, manually.
//! The push stage relies on internal muttability of the supplied `Observers`.
//!

/// Mutational stage is the normal fuzzing stage,
pub mod mutational;
pub use mutational::StdMutationalPushStage;

/// A push stage is a generator that returns a single testcase for each call.
pub trait PushStage<E, EM, S, Z>: Iterator {}
