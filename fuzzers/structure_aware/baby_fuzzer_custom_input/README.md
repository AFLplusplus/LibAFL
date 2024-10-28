# Baby fuzzer

This is a minimalistic fuzzer demonstrating how to employ mapping mutators to use default mutators on custom inputs. Custom inputs are necessary when the input to your program is a combination of parts, especially when those parts have different data types. Check multipart inputs if you have an input consisting of multiple parts of the same datatype and you don't need your mutation scheduler to be able to select which mutation is performed on which part.

The fuzzer runs on a single core until a crash occurs and then exits. The tested program is a simple Rust function without any instrumentation. For real fuzzing, you will want to add some sort to add coverage or other feedback.

You can run this example using `cargo run`.