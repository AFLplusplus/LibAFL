# Feedback

The Feedback is an entity that classify the outcome of an execution of the program under test as interesting or not.
Tipically, if an exeuction is interesting, the corresponding input used to feed the target program is added to a corpus.

Most of the times, the notion of Feedback is deeply linked to the Observer, but they are different concepts.

The Feedback, in most of the cases, process the information reported by one or more observer to decide if the execution is interesting.
The concept of "interestingness" is abstract, but tipically it is related to a novelty search (i.e. interesting inputs are those that reach a previosly unseen edge in the control flow graph).

As an example, given an Observer that reports all the size of memory allocations, a maximization Feedback can be used to maximize these sizes to sport patological inputs in terms of memory consumption.
