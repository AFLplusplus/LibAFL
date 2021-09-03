# Corpus

The Corpus is where testcases are stored. We define a Testcase as an Input and a set of related metadata like execution time for instance.

A Corpus can store testcases in diferent ways, for example on disk, or in memory, or implement a cache to speedup on disk storage.

Usually, a testcase is added to the Corpus when it is considered as interesting, but a Corpus is used also to store testcases that fulfill an objective (like crashing the tested program for instance).

Related to the Corpus, there is the way in which the fuzzer should ask for the next testcase to fuzz picking it from the Corpus. The taxonomy for this in LibAFL is CorpusScheduler, the entity representing the policy to pop testcases from the Corpus, FIFO for instance.

Speaking about the code, [`Corpus`](https://docs.rs/libafl/0/libafl/corpus/trait.Corpus.html) and [`CorpusScheduler`](https://docs.rs/libafl/0/libafl/corpus/trait.CorpusScheduler.html) are traits.
