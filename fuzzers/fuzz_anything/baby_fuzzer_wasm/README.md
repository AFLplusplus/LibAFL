# libafl-wasm

A brief demo demonstrating libafl's compatibility with WASM, and how to do it.

In this example, the entire LibAFL harness and target are present in a WASM binary, which is then loaded by [the example
webpage](pkg/index.html). To run this example, do `just build`, then open [the example webpage](pkg/index.html) in
your browser (via something like `python3 -m http.server`). The fuzzer will execute until finding a solution and will
write the fuzzer log to your console.

In a real fuzzing campaign, you would likely need to also create a LibAFL Corpus implementation which was backed by
JavaScript, and restart the fuzzing campaign by re-invoking the fuzzer and providing the associated corpora. This is
not demonstrated in this barebones example.
