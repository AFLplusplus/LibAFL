# Core Concepts

LibAFL is designed around some core concepts that we think can effectively abstract most of the other fuzzers designs.

Here, we discuss these concepts and provide some examples related to other fuzzers.

## Mutator

The Mutator is an entity that takes one or more Inputs and generates a new derived one.

Mutators can be composed and they are generally linked to a specific Input type.

There can be, for instance, a Mutator that applies more than a single type of mutation on the input. Consider a generic Mutator for a byte stream, bit flip is just one of the possible mutations but not the only one, there is also, for instance, the random replacement of a byte of the copy of a chunk.

This Mutator will simple schedule the application of some other Mutators.

## Generator

A Generator is a component designed to generate an Input from scratch.

Typically, a random generator is used to generate random inputs.

Generators are traditionally less used in Feedback-driven Fuzzing, but there are exceptions, like Nautilus, that uses a Grammar generator to create the initial corpus and a sub-tree Generator as a mutation of its grammar Mutator.

## Stage

A Stage is an entity that operates on a single Input got from the Corpus.

For instance, a Mutational Stage, given an input of the corpus, applies a Mutator and executes the generated input one or more time. How many times this has to be done can be scheduled, AFL for instance uses a performance score of the input to choose how many times the havoc mutator should be invoked. This can depend also on other parameters, for instance, the length of the input if we want to just apply a sequential bitflip, or be a fixed value.

A stage can also be an analysis stage, for instance, the Colorization stage of Redqueen that aims to introduce more entropy in a testcase or the Trimming stage of AFL that aims to reduce the size of a testcase.

