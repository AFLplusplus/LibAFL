# Migrating from libafl <0.9 to 0.9

Internal APIs of libafl have changed in version 0.9 to prefer associated types in cases where components were "fixed" to
particular versions of other components. As a result, many existing custom components will not be compatible between
versions prior to 0.9 and version 0.9.

## Scope

You are affected by this change if:
 - You specified explicit generics for a type (e.g., `MaxMapFeedback::<_, (), _>::new(...)`)
 - You implemented a custom component (e.g., `Mutator`, `Executor`, `State`, `Fuzzer`, `Feedback`, `Observer`, etc.)

If you did neither of these, congrats! You are likely unaffected by these changes.

### Migrating explicit generics

Migrating specific generics should be a quite simple process; you should review the API documentation for details on the
order of generics and replace them accordingly. Generally speaking, it should no longer be necessary to specify these
generics. 



See `fuzzers/` for examples of these changes.