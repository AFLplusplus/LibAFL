# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, etc.) working with
this repository -- either navigating LibAFL's own codebase, or helping
someone build a fuzzer that depends on LibAFL.

**Before opening a PR to this repository yourself, read the "Contribution
boundary" section at the bottom -- it matters and it isn't optional.**

## What this repo is

LibAFL is a Rust library of composable building blocks for constructing
custom fuzzers (Executor, Observer, Feedback, Input, Mutator, Corpus, State,
EventManager -- all swappable traits), rather than one fixed fuzzer. See
`README.md` for the full pitch and `crates/README.md` for the crate list.

Key facts an agent should know up front:

- MSRV (minimum supported Rust version): see `rust-version` in the root
  `Cargo.toml` and `crates/libafl/Cargo.toml` -- always read it fresh rather
  than assuming, it changes over time.
- LLVM tools (clang/clang++) are required for most instrumentation backends -- check the CI config for the currently tested version.
- The workspace is built with `cargo`; the `fuzzers/` examples are checked,
  built, and tested workspace-wide via `just` (see `Justfile` at the repo
  root) as well as individually with plain `cargo build`/`cargo run` inside
  each example's own directory.

## Repository layout

- `crates/` -- See `crates/README.md` for the full list of crates and what each one does.
- `fuzzers/` -- real, working example fuzzers, organized by category
  (see the decision guide below). **This is the most important directory
  for helping someone build a new fuzzer** -- the right move is almost
  always to find the closest existing example and adapt it, not to write
  fuzzer wiring from scratch.
- `utils/` -- standalone tools (some depend on the workspace, some don't;
  check each one's own `Cargo.toml` for a `[workspace]` table indicating it
  stands alone).
- `scripts/` -- formatting, linting, and CI-support scripts (see "Before
  finishing a change" below).
- `docs/` -- the LibAFL book sources.

## Helping someone build a fuzzer: decision guide

This is the part that matters most if you're an agent generating a new
fuzzer project for someone. Ask (or infer from context) two things: is
their target source-available or binary-only, and do they need something
beyond the common case? Then point at (and adapt) the closest real example
below -- don't invent fuzzer-wiring code from scratch when a working
example already demonstrates the pattern.

| Target situation | Look in | Concrete starting example |
|---|---|---|
| Source-available, "just give me a good default" (most common case) | `fuzzers/inprocess/` | `libfuzzer_libpng_launcher` -- in-process, multi-core, ASan on some cores; the README explicitly calls this "what most people want" |
| Binary-only, no source access, want AFL++-style forkserver | `fuzzers/forkserver/` | `forkserver_simple` (minimal) or `libafl-fuzz` (fuller afl-fuzz-alike) |
| Binary-only via dynamic instrumentation (no recompilation, incl. closed-source) | `fuzzers/binary_only/` | `frida_libpng` (Frida) or `qemu_launcher` (QEMU user-mode, full-featured multi-core) |
| Full-system / kernel / firmware / bootloader targets | `fuzzers/full_system/` | `qemu_linux_kernel`, `qemu_baremetal`, `nyx_launcher` depending on the system |
| Structured/grammar-based input -- use when the target expects a well-defined format (e.g. JSON, XML, network protocol, language parser) and byte-level mutation alone struggles to produce valid inputs | `fuzzers/structure_aware/` | `baby_fuzzer_gramatron`, `baby_fuzzer_nautilus`, or `baby_fuzzer_tokens` depending on the grammar formalism |
| WASM, Python, or another unusual host | `fuzzers/fuzz_anything/` | `baby_fuzzer_wasm`, `libafl_atheris` |

`fuzzers/README.md` has the authoritative, maintained version of this
categorization -- re-check it rather than relying solely on this table,
since new examples get added over time.

**Practical steps to scaffold a new fuzzer from an example:**

1. Copy the closest example's directory as a starting point (its
   `Cargo.toml` + `src/main.rs` are a known-working pair -- don't mix
   `main.rs` from one example with `Cargo.toml` from another without
   checking the dependency features line up).
2. Rename the package in `Cargo.toml`, and point the libafl/libafl_bolts dependencies at the latest crates.io version -- only use a local path dependency if you are developing LibAFL itself alongside your fuzzer.
3. Replace the harness closure (the function that feeds a byte slice, or
   whatever `Input` type is in use, into the actual target) with a call
   into the real target. Everything else in the example -- corpus setup,
   feedback, mutator, event manager, fuzz loop -- is reusable as-is for the
   common cases; only swap additional pieces (e.g. add a `MapFeedback` for
   real coverage, swap `BytesInput` for a structured input type) when the
   target actually needs it.
4. If the target needs real code-coverage feedback rather than a manual
   toy signal map, wire up instrumentation via `libafl_targets` +
   SanitizerCoverage (source-available) or the appropriate binary-only
   backend -- don't leave a fake/manual coverage map in place for a real
   target, it will misguide the fuzzer's mutation strategy.
5. For production-quality fuzzers, also add:
  - A cmplog / input-to-state (i2s) stage -- helps the fuzzer break through magic byte comparisons
  - A calibration stage -- measures stability and edge coverage of new corpus entries before committing them
  - A good seed corpus of valid inputs for your target -- random bytes alone will waste many executions on inputs rejected before reaching interesting code
  See `fuzzers/inprocess/libfuzzer_libpng_launcher` for an example that includes several of these stages.
6. Build and run (`cargo build`, `cargo run`), and confirm the corpus and
   `executions`/`exec/sec` stats are moving -- that's the sign the loop
   is actually exercising the target, not just compiling.

## Before finishing a change to LibAFL itself

If you're modifying code under `crates/`, `fuzzers/`, or `utils/` (as
opposed to just generating a new standalone project that depends on
LibAFL), run these before considering the change done:

- `just fmt` or `cargo +nightly fmt` -- formatting
- `just clippy` or `scripts/clippy.sh` (`scripts/clippy.ps1` on Windows) --
  linting
- `just no-default-features` or `cargo build --no-default-features` --
  `no_std` compatibility check; gate anything that needs `std` behind
  `#[cfg(feature = "std")]`
- `scripts/precommit.sh` runs the formatting + clippy checks together and
  is the closest local approximation of what CI will check

Code style conventions (generic ordering, `Cow<'static, str>` preference,
minimal `PhantomData`, alphabetized `where` clauses, and more) are
documented in detail in `CONTRIBUTING.md` under "LibAFL Code Rules" and
"Rules for Generics and Associated Types" -- follow those when writing or
editing code inside the workspace; this file intentionally doesn't
duplicate them so there's one source of truth.

If you change public APIs, add an entry to `MIGRATION.md` describing the
change, per `CONTRIBUTING.md`.

## Contribution boundary

`CONTRIBUTING.md` states LibAFL's contribution policy plainly: **the
project does not accept contributions with any form of AI assistance, and
will close PRs that appear to use it.**

That policy governs contributions *to LibAFL's own codebase* -- it does
not restrict what this file is for. This `AGENTS.md` exists to help an
agent assist someone building their *own* fuzzer, which depends on LibAFL
as a library, the same way any other documentation would. That's a
downstream use of LibAFL, not a contribution to it.

Concretely: it's fine to use this file to help generate a new fuzzer
project in someone's own repository. It is not a basis for an agent to
open a pull request against `AFLplusplus/LibAFL` on someone's behalf --
that remains governed by `CONTRIBUTING.md`, in full, regardless of what
this file says elsewhere.
