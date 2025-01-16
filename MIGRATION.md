
# 0.14.1 -> 0.15.0
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
  - For `UsesState`, you can access to the input type through `HasCorpus` and `Corpus` traits
  - The `State` trait is now private in favour of individual and more specific traits

# 0.14.0 -> 0.14.1
- Removed `with_observers` from `Executor` trait.
- `MmapShMemProvider::new_shmem_persistent` has been removed in favour of `MmapShMem::persist`. You probably want to do something like this: `let shmem = MmapShMemProvider::new()?.new_shmem(size)?.persist()?;`

# Pre 0.9 -> 0.9
- [Migrating from LibAFL <0.9 to 0.9](https://aflplus.plus/libafl-book/design/migration-0.9.html)