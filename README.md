# LibAFL, the fuzzer library.

Advanced Fuzzing Library - Slot your own Fuzzers together and extend their features, using Rust.

LibAFL is written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <mail@dmnk.co>.

It is released as Free and Open Source Software under the GNU Lesser General Public License V3.

## Example usages

We collect example fuzzers in `./fuzzers`.
The best-tested fuzzer is `./fuzzers/libfuzzer_libpng`, a clone of libfuzzer using libafl for a libpng harness.

## Roadmap for release

+ Minset corpus scheduler
+ Win32 shared mem and crash handler to have Windows in-process executor
+ Other objectives examples (e.g. maximize allocations to spot OOMs)
+ Fix issues for no_std
+ A macro crate with derive directives (e.g. for SerdeAny impl).
+ Good documentation
