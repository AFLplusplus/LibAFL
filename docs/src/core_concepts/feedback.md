# Feedback

The Feedback is an entity that classifies the outcome of an execution of the program under test as interesting or not.
Typically, if an execution is interesting, the corresponding input used to feed the target program is added to a corpus.

Most of the time, the notion of Feedback is deeply linked to the Observer, but they are different concepts.

The Feedback, in most of the cases, processes the information reported by one or more observers to decide if the execution is interesting.
The concept of "interestingness" is abstract, but typically it is related to a novelty search (i.e. interesting inputs are those that reach a previously unseen edge in the control flow graph).

As an example, given an Observer that reports all the sizes of memory allocations, a maximization Feedback can be used to maximize these sizes to sport pathological inputs in terms of memory consumption.

In terms of code, the library offers the [`Feedback`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html) trait.
It is used to implement functors that, given the state of the observers from the last execution, tells if the execution was interesting.
So to speak, it reduces the observations to a boolean result of [`is_interesting`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html#tymethod.is_interesting) - or not.
For this, a `Feedback` can store anything it wants to persist in the fuzzers's state.
This might be, for instance, the cumulative map of all edges seen so far, in the case of a feedback based on edge coverage.
This can be achieved by adding `Metadata` in [`init_state`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html#method.init_state) and accessing it later in `is_interesting`.
`Feedback` can also add custom metadata to a newly created [`Testcase`](https://docs.rs/libafl/latest/libafl/corpus/testcase/struct.Testcase.html) using [`append_metadata`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html#method.append_metadata).

Multiple Feedbacks can be combined into a boolean expression, considering for instance an execution as interesting if it triggers new code paths or execute in less time compared to the average execution time using [`feedback_or`](https://docs.rs/libafl/latest/libafl/macro.feedback_or.html).

On top, logic operators like `feedback_or` and `feedback_and` have a `_fast` variant (e.g. `feedback_or_fast`) where the second feedback will not be evaluated, if the value of the first feedback operand already answers the `interestingness` question so as to save precious performance.

Using `feedback_and_fast` in combination with [`ConstFeedback`](https://docs.rs/libafl/latest/libafl/feedbacks/enum.ConstFeedback.html#method.new), certain feedbacks can be disabled dynamically.

## Objectives

While feedbacks are commonly used to decide if an [`Input`](https://docs.rs/libafl/latest/libafl/inputs/trait.Input.html) should be kept for future mutations, they serve a double-purpose, as so-called `Objective Feedbacks`.
In this case, the `interestingness` of a feedback indicates if an `Objective` has been hit.
Commonly, these objectives would be a crash or a timeout, but they can also be used to detect if specific parts of the program have been reached, for sanitization, or a differential fuzzing success.
Objectives use the same trait as a normal [`Feedback`](https://docs.rs/libafl/latest/libafl/feedbacks/trait.Feedback.html) and the implementations can be used interchangeably.

The only difference is that `interesting` Objectives won't be mutated further, and are counted as `Solutions`, a successful fuzzing campaign.
