# baby grimoire fuzzer
This fuzzer shows how to implement [Grimoire fuzzer](https://www.usenix.org/system/files/sec19-blazytko.pdf), a fully automated coverage-guided fuzzer which works without any form of human interaction or pre-configuration. `libafl::mutators::grimoire` provides four mutators :
`GrimoireExtensionMutator`,`GrimoireRecursiveReplacementMutator`,
`GrimoireStringReplacementMutator`,`GrimoireRandomDeleteMutator`.

The fuzzer will regard all files in `./corpus` as inputs. Inputs will be mutated by `mutator`(havoc_mutations) and `grimoire_mutator`. `harness` will firstly check if `input` contains substring `fn` or `pippopippo` then print the input mutated by `grimoire_mutator`.
> **_NOTE:_**  This harness is not designed for a crash, so `cargo run` will not terminate.