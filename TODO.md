# Jetbot Tasks

- [x] Fix redundant references in `println!` in `crates/libafl_targets/build.rs` around line 323 to resolve cargo clippy errors. (validated)
- [x] Fix redundant references in `write!` in `crates/libafl_core/src/lib.rs` (lines 364-430) to resolve cargo clippy errors. (validated)
- [x] Add unit tests for the formatting logic in `crates/libafl_core/src/lib.rs` that uses `write!` to ensure edge cases are handled correctly. (validated)
- [x] Investigate and resolve the `src/dump-cfg-pass.cc` compilation failure in `libafl_cc` (or properly disable it if truly unused). (validated)
- [x] Fix standard library import in `crates/ll_mp/src/lib.rs` line 135 to use `core` instead of `std` to resolve clippy error. (validated)
- [x] Remove redundant reference `&` in `panic!` argument in `crates/ll_mp/src/lib.rs` around line 1835. (validated)
- [x] Remove redundant reference `&` in `assert!` argument in `crates/ll_mp/src/lib.rs` around line 2087. (validated)
- [x] Add unit tests for `ll_mp` specific edge cases around panic handling and asserts to ensure robustness. (validated)
