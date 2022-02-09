# Feedback

The [`Feedback`](https://docs.rs/libafl/0/libafl/feedbacks/trait.Feedback.html) is an entity that classifies the outcome of an execution of the program under test as interesting or not.
Typically, if an execution is interesting, the corresponding input used to feed the target program is added to a corpus.

Most of the time, the notion of [`Feedback`](https://docs.rs/libafl/0/libafl/feedbacks/trait.Feedback.html) is deeply linked to the Observer, but they are different concepts.

Usually, the [`Feedback`](https://docs.rs/libafl/0/libafl/feedbacks/trait.Feedback.html) processes the information reported by one or more observers to decide if the execution is interesting.
The concept of "interestingness" is abstract.
Typically it is related to a novelty search (i.e., interesting inputs are those that reach a previously unseen edge in the control flow graph).

As an example, given an Observer that reports all the sizes of memory allocations, a maximization Feedback can be used to maximize these sizes to spot pathological inputs in terms of memory consumption.

In terms of code, the library offers the [`Feedback`](https://docs.rs/libafl/0/libafl/feedbacks/trait.Feedback.html) and the [`FeedbackState`](https://docs.rs/libafl/0/libafl/feedbacks/trait.FeedbackState.html) traits.
The first is used to implement functors that show if the execution was interesting given the state of the observers from the last execution. The second is closely tied to a `Feedback` and contains the data that the feedback needs to persist in the fuzzers's state, for instance, the cumulative map holding all the edges seen so far in the case of edge coverage.

Multiple Feedbacks can be combined into boolean formula, considering an execution as interesting if it triggers new code paths or executes in less time than the average execution time using [`feedback_or`](https://docs.rs/libafl/0/libafl/macro.feedback_or.html).

Combining feedbacks using `feedback_or` or `feedback_and` works in a `fast` or an `eager` variant.
The `fast` variants cancel execution early, while the `eager` variants will evaluate them completely.
For example, the `is_intersting()` method of `feedback_and_fast(f1, f2)` won't evaluate `f2` if `f1` already returned `false` for it's `is_interesting`, while the `eager` method would continue to evaluate `f2` (but reach the same overall result).
The `eager` methods are helpful if the second feedback needs to run for every execution, such as bookkeeping tasks.

## Objectives

Using the same `Feedback` infrastructure, `LibAFL` supports `Objectives`.
Apart from a few special objectives for crashes and timeouts, objectives behave precisely like regular feedbacks.
The main difference is that the interesting objectives get stored into the fuzzer's `solutions` and will not get used for further mutations.
The solutions can also be stored with additional metadata depending on the setting.