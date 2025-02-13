# Generator

A Generator is a component designed to generate an Input from scratch.

Typically, a random generator is used to generate random inputs.

Generators are traditionally less used in Feedback-driven Fuzzing, but there are exceptions, like Nautilus, that uses a Grammar generator to create the initial corpus and a sub-tree Generator as a mutation of its grammar Mutator.

In the code, [`Generator`](https://docs.rs/libafl/latest/libafl/generators/trait.Generator.html) is a trait.
