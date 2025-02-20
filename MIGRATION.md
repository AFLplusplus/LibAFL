# Migration Notes For LibAFL Versions

## 0.15.0 -> 0.16.0

- `EventManager` is refactored to avoid calling function from `Fuzzer`, thus we do not evaluate testcases in `EventManager` anymore.
  - Now we have `EventReceiver` in `events` module, and `EventProcessor` in `fuzzer` module.
  - `EventReceiver` is responsible for receiving testcases and delegates its evaluation to `EventProcessor`.
  - `EventProcessor` is responsible for evaluating the testcases passed by the `EventReceiver`.
  - Since we don't evaluate testcases in the `EventManager` anymore. `on_fire` and `post_exec` have been deleted from `EventManagerHook`.
  - Similarly `pre_exec` has been renamed to `pre_receive`.
- `AsanModule` now uses a `builder()` method for constructing its instances.
- `Monitor` is refactored. Most statistics have been extracted into an individual `stats` module under `monitors`.
  - There is a `ClientStatsManager` to manage client statistics, and is owned by `EventManager`. Most of previous `Monitor`'s trait methods have been moved to the `ClientStatsManager`.
  - `user_monitor` has been renamed to `user_stats`, `introspection_monitor` has been renamed to `introspection_stats`, perf-related structure definitions have been renamed, and all were moved to the `stats` module.
  - `OnDiskTomlMonitor`, `OnDiskJsonMonitor`, `OnDiskJsonAggregateMonitor` are now no longer takes a base monitor to wrap. If you want to use multiple monitors together, simply use a `tuple_list`.
- `MultipartInput` is now implemented as key-value tuples in a `ListInput`. The interface slightly changed, all functionality is maintained.
  - Instead of names, `MultipartInput` uses generic `key`s (function names were changed accordingly).
  - If you don't need the keys to identify individual parts, consider using `ListInput` directly.

## 0.14.1 -> 0.15.0

- `MmapShMem::new` and `MmapShMemProvider::new_shmem_with_id` now take `AsRef<Path>` instead of a byte array for the filename/id.
- The closure passed to a `DumpToDiskStage` now provides the `Testcase` instead of just the `Input`.
- `StatsStage` is deleted, and it is superceded by `AflStatsStage`
- Renamed and changed mapping mutators to take borrows directly instead of `MappedInput`s. See `baby_fuzzer_custom_input` for example usage
  - Related: `MutVecInput` is deprecated in favor of directly using `&mut Vec<u8>`
  - Related: `MappedInputFunctionMappingMutator` and `ToMappedInputFunctionMappingMutatorMapper` have been removed as now duplicates of `MappingMutator` (previously `FunctionMappingMutator`) and `ToMappingMutator` (previously `ToFunctionMappingMutatorMapper`)
  - Related: `ToOptionMappingMutatorMapper` and `ToFunctionMappingMutatorMapper` have been renamed to `ToOptionalMutator` and `ToMappingMutator` respectively
- `Qemu` cannot be used to initialize `Emulator` directly anymore. Instead, `Qemu` should be initialized through `Emulator` systematically if `Emulator` should be used.
  - Related: `EmulatorBuilder` uses a single function to provide a `Qemu` initializer: `EmulatorBuilder::qemu_parameters`. For now, it can be either a `Vec<String>` or a `QemuConfig` instance.
  - Related: Qemu's `AsanModule` does not need any special call to `Qemu` init methods anymore. It is now possible to simply initialize `AsanModule` (or `AsanGuestModule`) with a reference to the environment as parameter.
  - `CustomBufHandlers` has been deleted. Please use `EventManagerHooksTuple` from now on.
- Trait restrictions have been simplified
  - The `UsesState` and `UsesInput` traits have been removed in favor of regular Generics.
  - For the structs/traits that used to use `UsesState`, we bring back the generic for the state.
  - `Input` is now only accessible through generic. `Input` associated types have been definitely removed.
  - `HasCorpus` bound has been removed in many places it was unused before.
  - `StdMutationalStage::transforming` must now explicitly state the Inputs types. As a result, `StdMutationalStage::transforming` must be written `StdMutationalStage::<_, _, FirstInputType, SecondInputType, _, _, _>::transforming`.
  - The `State` trait is now private in favour of individual and more specific traits
- Restrictions from certain schedulers and stages that required their inner observer to implement `MapObserver` have been lifted in favor of requiring `Hash`
  - Related: removed `hash_simple` from `MapObserver`

## 0.14.0 -> 0.15.0

- Removed `with_observers` from `Executor` trait.
- `MmapShMemProvider::new_shmem_persistent` has been removed in favour of `MmapShMem::persist`. You probably want to do something like this: `let shmem = MmapShMemProvider::new()?.new_shmem(size)?.persist()?;`

## Pre 0.9 -> 0.9

- [Migrating from LibAFL <0.9 to 0.9](https://aflplus.plus/libafl-book/design/migration-0.9.html)