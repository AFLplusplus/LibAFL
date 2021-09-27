# Feedback

The Feedback is an entity that classifies the outcome of an execution of the program under test as interesting or not.
Typically, if an execution is interesting, the corresponding input used to feed the target program is added to a corpus.

Most of the times, the notion of Feedback is deeply linked to the Observer, but they are different concepts.

The Feedback, in most of the cases, processes the information reported by one or more observers to decide if the execution is interesting.
The concept of "interestingness" is abstract, but typically it is related to a novelty search (i.e. interesting inputs are those that reach a previously unseen edge in the control flow graph).

As an example, given an Observer that reports all the sizes of memory allocations, a maximization Feedback can be used to maximize these sizes to sport pathological inputs in terms of memory consumption.

In terms of code, the library offers the [`Feedback`](https://docs.rs/libafl/0/libafl/feedbacks/trait.Feedback.html) and the [`FeedbackState`](https://docs.rs/libafl/0/libafl/feedbacks/trait.FeedbackState.html) traits.
The first is used to implement functors that, given the state of the obversers from the last execution, tells if the execution was interesting. The second is tied with `Feedback` and it is the state of the data that the feedback wants to persist in the fuzzers's state, for instance the cumulative map holding all the edges seen so far in the case of a feedback based on edge coverage.

Multiple Feedbacks can be combined into boolean formula, considering for instance an execution as interesting if it triggers new code paths or execute in less time compared to the average execution time using [`feedback_or`](https://docs.rs/libafl/0/libafl/macro.feedback_or.html).

TODO objective feedbacks and fast feedback logic operators
