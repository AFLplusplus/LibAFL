# Observer

An Observer is an entity that provides an information observed during the execution of the program under test to the fuzzer.

The information contained in the Observer is not preserved across executions, but it may be serialized and passed on to other nodes if an `Input` is considered `interesting`, and added to the `Corpus`.

As an example, the coverage map, filled during the execution to report the executed edges used by fuzzers such as AFL and `HonggFuzz` can be considered an observation. Another `Observer` can collect the time spent executing a run, the program output, or a more advanced observation, like maximum stack depth at runtime.
This information is an observation of a dynamic property of the program.

In terms of code, in the library this entity is described by the [`Observer`](https://docs.rs/libafl/latest/libafl/observers/trait.Observer.html) trait.

In addition to holding the volatile data connected with the last execution of the target, the structures implementing this trait can define some execution hooks that are executed before and after each fuzz case. In these hooks, the observer can modify the fuzzer's state.

The fuzzer will act based on these observers through a [`Feedback`](./feedback.md), that reduces the observation to the choice if a testcase is `interesting` for the fuzzer, or not.

## Observer State Restoration and Restarts

**Important:** If your observer has configuration or state that must persist across fuzzer restarts (for example, when using an EventRestarter), you **must** store this information in the fuzzer state (typically as metadata), and restore it in the `on_state_restore` method of your observer. Otherwise, any changes made to the observer's configuration at runtime will be lost after a restart.

LibAFL provides:
- The `Observer::on_state_restore(&self, state: &S)` method, which you can override to re-sync your observer's configuration from the fuzzer state after a restart.
- The `notify_observers_on_state_restore` utility function, which calls `on_state_restore_all` for all observers in a tuple.

**Example:**

```rust
// After restoring the state (e.g., from a restarting event manager):
let (mut state, mut mgr) = setup_restarting_mgr_std(...)?;
let mut observers = ...; // your observers tuple
libafl::observers::notify_observers_on_state_restore(&mut observers, &state);
```

If your observer needs to restore configuration:

```rust
impl<I, S> Observer<I, S> for MyObserver {
    // ...
    fn on_state_restore(&mut self, state: &S) {
        // Restore configuration from state metadata
        if let Some(meta) = state.metadata::<MyObserverConfig>() {
            self.config = meta.clone();
        }
    }
}
```

See also the documentation in the `Observer` trait for more details.
