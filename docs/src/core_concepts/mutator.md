# Mutator

The Mutator is an entity that takes one or more Inputs and generates a new derived one.

Mutators can be composed and they are generally linked to a specific Input type.

There can be, for instance, a Mutator that applies more than a single type of mutation on the input. Consider a generic Mutator for a byte stream, bit flip is just one of the possible mutations but not the only one, there is also, for instance, the random replacement of a byte of the copy of a chunk.

In LibAFL, [`Mutator`](https://docs.rs/libafl/0/libafl/mutators/trait.Mutator.html) is a trait.
