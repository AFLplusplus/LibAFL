## baby nautilus fuzzer
[Nautilus](https://www.ndss-symposium.org/ndss-paper/nautilus-fishing-for-deep-bugs-with-grammars/) is a coverage-guided and grammar-based fuzzer. It needs to read the mruby's context-free grammar stored in `grammar.json`. And then use the corresponding feedback, generator, and mutator to fuzz.
`libafl::mutators::nautilus` contains:
```
NautilusInput,NautilusContext
NautilusChunksMetadata,NautilusFeedback
NautilusGenerator
NautilusRandomMutator,NautilusRecursionMutator,NautilusSpliceMutator
```
