# Jetbot Tasks

- [x] Fix redundant references in `println!` in `crates/libafl_targets/build.rs` around line 323 to resolve cargo clippy errors. (validated)
- [x] Fix redundant references in `write!` in `crates/libafl_core/src/lib.rs` (lines 364-430) to resolve cargo clippy errors. (validated)
- [x] Add unit tests for the formatting logic in `crates/libafl_core/src/lib.rs` that uses `write!` to ensure edge cases are handled correctly. (validated)
- [x] Investigate and resolve the `src/dump-cfg-pass.cc` compilation failure in `libafl_cc` (or properly disable it if truly unused). (validated)
- [x] Fix standard library import in `crates/ll_mp/src/lib.rs` line 135 to use `core` instead of `std` to resolve clippy error. (validated)
- [x] Remove redundant reference `&` in `panic!` argument in `crates/ll_mp/src/lib.rs` around line 1835. (validated)
- [x] Remove redundant reference `&` in `assert!` argument in `crates/ll_mp/src/lib.rs` around line 2087. (validated)
- [x] Add unit tests for `ll_mp` specific edge cases around panic handling and asserts to ensure robustness. (validated)
- [x] Refactor `ASAN_LOG_PATH` in `crates/libafl/src/observers/stacktrace.rs` (line 249) to generate unique file paths rather than a hardcoded `./asanlog` to prevent parallel runs from clobbering each other. (validated)
- [x] Add unit tests for the newly refactored `ASAN_LOG_PATH` generation in `crates/libafl/src/observers/stacktrace.rs` to verify that concurrent instantiations produce distinct and valid file paths. (validated)
- [ ] Implement logic to handle `corpus_counts` decreasing due to removals in `crates/libafl/src/schedulers/weighted.rs` (around line 349) to ensure scheduler weight consistency.
- [ ] Optimize memory allocations in `crates/libafl/src/events/multi_machine.rs` (around line 393) to improve event handling performance and reduce allocator overhead.
