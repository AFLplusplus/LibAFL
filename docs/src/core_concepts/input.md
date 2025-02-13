# Input

Formally, the input of a program is the data taken from external sources that affect the program behavior.

In our model of an abstract fuzzer, we define the Input as the internal representation of the program input (or a part of it).

In the straightforward case, the input of the program is a byte array and in fuzzers such as AFL we store and manipulate exactly these byte arrays.

But it is not always the case. A program can expect inputs that are not linear byte arrays (e.g. a sequence of syscalls forming a use case or protocol) and the fuzzer does not represent the Input in the same way that the program consumes it.

In case of a grammar fuzzer for instance, the Input is generally an Abstract Syntax Tree because it is a data structure that can be easily manipulated while maintaining the validity, but the program expects a byte array as input, so just before the execution, the tree is serialized to a sequence of bytes.

In the Rust code, an [`Input`](https://docs.rs/libafl/latest/libafl/inputs/trait.Input.html) is a trait that can be implemented only by structures that are serializable and have only owned data as fields.

While most fuzzers use a normal `BytesInput`, more advanced ones use inputs that include special inputs for grammar fuzzing ([GramatronInput](https://docs.rs/libafl/latest/libafl/inputs/gramatron/struct.GramatronInput.html) or `NautilusInput` on Rust nightly), as well as the token-level [EncodedInput](https://docs.rs/libafl/latest/libafl/inputs/encoded/struct.EncodedInput.html).
