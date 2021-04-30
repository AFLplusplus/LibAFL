//! Bolts are no conceptual fuzzing elements, but they keep libafl-based fuzzers together.

pub mod bindings;

#[cfg(feature = "llmp_compression")]
pub mod compress;

pub mod llmp;
pub mod os;
pub mod ownedref;
pub mod serdeany;
pub mod shmem;
pub mod tuples;
