# Architecture

The LibAFL architecture is built around some entities to allow code reuse and low-cost abstractions.

Initially, we started thinking to implement LibAFL in an Object Oriented language, such C++. When we landed to Rust, we immediately changed our idea as we realized that, while Rust allow a sort of OOP pattern, we can build the library using a more sane approach like the one described in [this blogpost](https://kyren.github.io/2018/09/14/rustconf-talk.html) about game design in Rust.

The LibAFL code reuse meachanism is so based on components rather than sub-classes, but there are still some OOP patterns in the library.

Thinking about similar fuzzers, you can observe that most of the times the data structures that are modified are the ones related to testcases and the fuzzer global state.

Beside the entities described previously, we introduce the Testcase and State entities. The Testcase is a container for an Input stored in the Corpus and its metadata (so, in the implementation, the Corpus stores Testcases) and the State contains all the metadata that are evolved while running the fuzzer, Corpus included.


