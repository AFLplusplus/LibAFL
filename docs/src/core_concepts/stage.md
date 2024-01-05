# Stage

A Stage is an entity that operates on a single Input received from the Corpus.

For instance, a Mutational Stage, given an input of the corpus, applies a Mutator and executes the generated input one or more times. How many times this has to be done can be scheduled, AFL for instance uses a performance score of the input to choose how many times the havoc mutator should be invoked. This can depend also on other parameters, for instance, the length of the input if we want to just apply a sequential bitflip, or a fixed value.

A stage can also be an analysis stage, for instance, the Colorization stage of Redqueen that aims to introduce more entropy in a testcase or the Trimming stage of AFL that aims to reduce the size of a testcase.

There are several stages in the LibAFL codebase implementing the [`Stage`](https://docs.rs/libafl/latest/libafl/stages/trait.Stage.html) trait.
