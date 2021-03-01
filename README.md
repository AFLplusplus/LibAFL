# LibAFL, the fuzzer library.

Advanced Fuzzing Library - Slot your own fuzzers together and extend their features using Rust.

LibAFL is written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <mail@dmnk.co>.

It is released as Free and Open Source Software under the GNU Lesser General Public License V3.



## Example usages

We collect example fuzzers in `./fuzzers`. They can be build using `cargo build --example [fuzzer_name] --release`
The best-tested fuzzer is `./fuzzers/libfuzzer_libpng`, a clone of libfuzzer using libafl for a libpng harness.
See its readme [here](./fuzzers/libfuzzer_libpng/README.md).

If you want to get a quick overview, run `cargo doc`.
Feel free to open issues or contact us directly. Thank you for your support. <3

## The Core Concepts

We're still working on the documentation. In the meantime, you can watch the Video from last year's Rc3, here:
[![Video explaining libAFL's core concepts](http://img.youtube.com/vi/3RWkT1Q5IV0/3.jpg)](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO")
## Roadmap for release

+ ~~Minset corpus scheduler~~ still doc missing
+ Win32 shared mem and crash handler to have Windows in-process executor
+ Other feedbacks examples (e.g. maximize allocations to spot OOMs)
+ Other objectives examples (e.g. execution of a given program point)
+ ~~A macro crate with derive directives (e.g. for SerdeAny impl)~~ just `derive(SerdeAny)`, missing doc.
+ Good documentation

For further TODOs, see [TODO.md](./TODO.md)
