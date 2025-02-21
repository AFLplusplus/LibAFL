# Summary

[The LibAFL Fuzzing Library](./libafl.md)

[Introduction](./introduction.md)

- [Getting Started](./getting_started/getting_started.md)
  - [Setup](./getting_started/setup.md)
  - [Build](./getting_started/build.md)
  - [Crates](./getting_started/crates.md)

- [Baby Fuzzer](./baby_fuzzer/baby_fuzzer.md)
  - [More Examples](./baby_fuzzer/more_examples.md)
- [Core Concepts](./core_concepts/core_concepts.md)
  - [Observer](./core_concepts/observer.md)
  - [Executor](./core_concepts/executor.md)
  - [Feedback](./core_concepts/feedback.md)
  - [Input](./core_concepts/input.md)
  - [Corpus](./core_concepts/corpus.md)
  - [Mutator](./core_concepts/mutator.md)
  - [Generator](./core_concepts/generator.md)
  - [Stage](./core_concepts/stage.md)

- [Design](./design/design.md)
  - [Architecture](./design/architecture.md)
  - [Metadata](./design/metadata.md)
  - [Migrating from LibAFL <0.9 to 0.9](./design/migration-0.9.md)
  - [Migrating from LibAFL <0.11 to 0.11](./design/migration-0.11.md)

- [Message Passing](./message_passing/message_passing.md)
  - [Spawning Instances](./message_passing/spawn_instances.md)
  - [Configurations](./message_passing/configurations.md)

- [Tutorial](./tutorial/tutorial.md)
  - [Introduction](./tutorial/intro.md)

- [Advanced Features](./advanced_features/advanced_features.md)
  - [Binary-Only Fuzzing with `Frida`](./advanced_features/frida.md)
  - [Concolic Tracing & Hybrid Fuzzing](./advanced_features/concolic.md)
  - [LibAFL in `no_std` environments (Kernels, Hypervisors, ...)](./advanced_features/no_std.md)
  - [Snapshot Fuzzing in Nyx](./advanced_features/nyx.md)
  - [StatsD Monitor](./advanced_features/statsd_monitor.md)
