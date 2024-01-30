# Corpus

The Corpus is where testcases are stored. We define a Testcase as an Input and a set of related metadata like execution time for instance.

A Corpus can store testcases in different ways, for example on disk, or in memory, or implement a cache to speedup on disk storage.

Usually, a testcase is added to the Corpus when it is considered as interesting, but a Corpus is used also to store testcases that fulfill an objective (like crashing the program under test for instance).

Related to the Corpus is the way in which the next testcase (the fuzzer would ask for) is retrieved from the Corpus. The taxonomy for this handling in LibAFL is Scheduler, the entity representing the policy to pop testcases from the Corpus, in a FIFO fashion for instance.

Speaking about the code, [`Corpus`](https://docs.rs/libafl/latest/libafl/corpus/trait.Corpus.html) and [`Scheduler`](https://docs.rs/libafl/latest/libafl/schedulers/trait.Scheduler.html) are traits.
