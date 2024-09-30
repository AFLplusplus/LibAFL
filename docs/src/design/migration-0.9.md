# Migrating from LibAFL <0.9 to 0.9

Internal APIs of LibAFL have changed in version 0.9 to prefer associated types in cases where components were "fixed" to
particular versions of other components. As a result, many existing custom components will not be compatible between
versions prior to 0.9 and version 0.9.

## Reasons for this change

When implementing a trait with a generic, it is possible to have more than one instantiation of that generic trait. As a
result, everywhere where consistency across generic types was required to implement a trait, it needed to be properly
and explicitly constrained at every point. This led to `impl`s which were at best difficult to debug and, at worst,
incorrect and caused confusing bugs for users.

For example, consider the  `MapCorpusMinimizer` implementation (from <0.9) below:

```rust,ignore
impl<E, I, O, S, TS> CorpusMinimizer<I, S> for MapCorpusMinimizer<E, I, O, S, TS>
where
    E: Copy + Hash + Eq,
    I: Input,
    for<'a> O: MapObserver<Entry = E> + AsIter<'a, Item = E>,
    S: HasMetadata + HasCorpus<I>,
    TS: TestcaseScore<I, S>,
{
    fn minimize<CS, EX, EM, OT, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut EX,
        manager: &mut EM,
        state: &mut S,
    ) -> Result<(), Error>
    where
        CS: Scheduler<I, S>,
        EX: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        EM: EventManager<EX, I, S, Z>,
        OT: ObserversTuple<S>,
        Z: Evaluator<EX, EM, I, S> + HasScheduler<CS, I, S>,
    {
        // --- SNIP ---
    }
}
```

It was previously necessary to constrain every generic using a slew of other generics; above, it is necessary to
constrain the input type (`I`) for every generic, despite the fact that this was already made clear by the state (`S`)
and that the input will necessarily be the same over every implementation for that type.

Below is the same code, but with the associated types changes (note that some generic names have changed):

```rust,ignore
impl<E, O, T, TS> CorpusMinimizer<E> for MapCorpusMinimizer<E, O, T, TS>
where
    E: UsesState,
    for<'a> O: MapObserver<Entry = T> + AsIter<'a, Item = T>,
    E::State: HasMetadata + HasCorpus,
    T: Copy + Hash + Eq,
    TS: TestcaseScore<E::State>,
{
    fn minimize<CS, EM, Z>(
        &self,
        fuzzer: &mut Z,
        executor: &mut E,
        manager: &mut EM,
        state: &mut E::State,
    ) -> Result<(), Error>
    where
        E: Executor<EM, Z> + HasObservers,
        CS: Scheduler<State=E::State>,
        EM: UsesState<State=E::State>,
        Z: HasScheduler<CS, State=E::State>,
    {
        // --- SNIP ---
    }
}
```

The executor is constrained to `EM` and `Z`, with each of their respective states being constrained to `E`'s state. It
is no longer necessary to explicitly define a generic for the input type, the state type, or the generic type, as these
are all present as associated types for `E`. Additionally, we don't even need to specify any details about the observers
(`OT` in the previous version) as the type does not need to be constrained and is not shared by other types.

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

### Migrating component types

If you implemented a Mutator, Executor, State, or another kind of component, you must update your implementation. The
main changes to the API are in the use of "Uses*" for associated types.

In many scenarios, Input, Observer, and State generics have been moved into traits with associated types (namely,
"UsesInput", "UsesObservers", and "UsesState". These traits are required for many existing traits now and are very
straightforward to implement. In a majority of cases, you will have generics on your custom implementation or a fixed
type to implement this with. Thankfully, Rust will let you know when you need to implement this type.

As an example, `InMemoryCorpus` before 0.9 looked like this:

```rust,ignore
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
    current: Option<usize>,
}

impl<I> Corpus<I> for InMemoryCorpus<I>
where
    I: Input,
{
    // --- SNIP ---
}
```

After 0.9, all `Corpus` implementations are required to implement `UsesInput`. Also `Corpus` no longer has a generic for
the input type (as it is now provided by the UsesInput impl). The migrated implementation is shown below:

```rust,ignore
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
    current: Option<usize>,
}

impl<I> UsesInput for InMemoryCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for InMemoryCorpus<I>
where
    I: Input,
{
    // --- SNIP ---
}
```

Now, `Corpus` cannot be accidentally implemented for another type other than that specified by `InMemoryCorpus`, as it
is fixed to the associated type for `UsesInput`.

A more complex example of migration can be found in the "Reasons for this change" section of this document.

## Observer Changes

Additionally, we changed the Observer API, as the API in 0.8 led to undefined behavior.
At the same time, we used the change to simplify the common case: creating an `StdMapObserver`
from libafl_target's `EDGES_MAP`.
In the future, instead of using:

```rust,ignore
let edges = unsafe { &mut EDGES_MAP[0..EDGES_MAP_DEFAULT_SIZE] };
let edges_observer = StdMapObserver::new("edges", edges);
```

creating the edges observer is as simple as using the new `std_edges_map_observer` function.

```rust,ignore
let edges_observer = unsafe { std_edges_map_observer("edges") };
```

Alternatively, `StdMapObserver::new` will still work, but now the whole method is marked as `unsafe`.
The reason is that the caller has to make sure `EDGES_MAP` (or other maps) are not moved or freed in memory,
for the lifetime of the `MapObserver`.
This means that the buffer should either be `static` or `Pin`.
