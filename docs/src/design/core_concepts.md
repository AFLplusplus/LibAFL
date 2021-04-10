# Core Concepts

LibAFL is designed around some core concepts that we think can effectively abstract most of the other fuzzers designs.

Here, we discuss these concepts and provide some examples related to other fuzzers.

TODO add links to trait definitions in docs.rs

## Observer

An Observer, or Observation Channel, is an entity that provides an information observed during the execution of the program under test to the fuzzer.

The information contained in the Observer is not preserved cross executions.

As an example, the coverage shared map filled during the execution to report the executed edges used by fuzzers such as AFL and HoggFuzz can be considered an Observation Channel.
This information is not preserved accros runs and it is an observation of a dynamic property of the program.

## Executor

In different fuzzers, the concept of executing the program under test each run is now always the same.
For instance, for in-memory fuzzers like libFuzzer an execution is a call to an harness function, for hypervisor-based fuzzers like [kAFL](https://github.com/IntelLabs/kAFL) instead an entire operating system is started from a snapshot each run.

In our model, an Executor is the entity that defines not only how to execute the target, but all the volatile operations that are related to just a single run of the target.

So the Executor is for instance reponsible to inform the program about the input that the fuzzer wants to use in the run, writing to a memory location for instance or passing it as a parameter to the harness function.

It also holds a set of Observers, as thay are related to just a single run of the target.

## Feedback

The Feedback is an entity that classify the outcome of an execution of the program under test as interesting or not.
Tipically, if an exeuction is interesting, the corresponding input used to feed the target program is added to a corpus.

Most of the times, the notion of Feedback is deeply linked to the Observer, but they are different concepts.

The Feedback, in most of the cases, process the information reported by one or more observer to decide if the execution is interesting.
The concept of "interestingness" is abstract, but tipically it is related to a novelty search (i.e. interesting inputs are those that reach a previosly unseen edge in the control flow graph).

As an example, given an Observer that reports all the size of memory allocations, a maximization Feedback can be used to maximize these sizes to sport patological inputs in terms of memory consumption.

## Input

Formally, the input of a program is the data taken from external sources and that affect the program behaviour.

In our model of an abstarct fuzzer, we define the Input as the internal representation of the program input (or a part of it).

In the straightforward case, the input of the program is a byte array and in fuzzers such as AFL we store an manipulate exaclty these byte arrays.

But it is not always the case. A program can expect inputs that are not byte arrays (e.g. a sequence of syscalls) and the fuzzer does not represent the Input in the same way that the program consume it.

In case of a grammar fuzzer for instance, the Input is generally an Abstract Syntax Tree because it is a data structure that can be easily manipulated while maintaining the validity, but the program expects a byte array as input so, just before the execution, the tree is serialized to a sequence of bytes.

## Corpus

The Corpus is where testcases are stored. A Testcase is defined as an Input and a set of related metadata like execution time for instance.

For instance, a Corpus can store testcases on disk, or in memory, or implement a cache to speedup on disk storage.

Usually, a testcase is added to the Corpus when it is considered as interesting.

## Mutator

The Mutator is an entitiy that takes one or more Inputs and generates a new derived one.

Mutators can be composed and they are generally linked to a specific Input type.

There can be, for instance, a Mutator that applies more than a single type of mutation on the input. Consider a generic Mutator for a byte stream, bit flip is just one of the possible mutations but not the single one, there is also, for instance, the random replacement of a byte of the copy of a chunk.

This Mutator will simple schedule the application of some other Mutators.

## Generator

A Generator is a component designed to generate an Input from scratch.

Tipically, a random generator is used to generate random inputs.

Generators are traditionally less used in Feedback-driven Fuzzing, but there are exceptions, like Nautilus, that uses a Grammar generator to create the initial corpus and a sub-tree Generator as a mutation of its grammar Mutator.

## Stage

A Stage is an entity that operates on a single Input got from the Corpus.

For instamce, a Mutational Stage, given an input of the corpus, applies a Mutator and executes the generated input one or more time. How many times this has to be done can be scheduled, AFL for instance use a performance score of the input to choose how many times the havoc mutator should be invoked. This can depends also on other parameters, for instance, the length of the input if we want to just apply a sequential bitflip, or be a fixed value.

A stage can be also an analysis stage, for instance, the Colorization stage of Redqueen that aims to introduce more entropy in a testcase or the Trimming stage of AFL that aims to reduce the size of a testcase.

