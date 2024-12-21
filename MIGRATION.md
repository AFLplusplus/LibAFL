
# 0.14.1 -> 0.15.0
- `MmapShMem::new` and `MmapShMemProvider::new_shmem_with_id` now take `AsRef<Path>` instead of a byte array for the filename/id.
- The closure passed to a `DumpToDiskStage` now provides the `Testcase` instead of just the `Input`.
- `StatsStage` is deleted, and it is superceded by `AflStatsStage`
- Renamed and changed mapping mutators to take borrows directly instead of `MappedInput`s. See `baby_fuzzer_custom_input` for example usage
  - Related: `MutVecInput` is deprecated in favor of directly using `&mut Vec<u8>`
  - Related: `MappedInputFunctionMappingMutator` and `ToMappedInputFunctionMappingMutatorMapper` have been removed as now duplicates of `MappingMutator` (previously `FunctionMappingMutator`) and `ToMappingMutator` (previously `ToFunctionMappingMutatorMapper`)
  - Related: `ToOptionMappingMutatorMapper` and `ToFunctionMappingMutatorMapper` have been renamed to `ToOptionalMutator` and `ToMappingMutator` respectively

# 0.14.0 -> 0.14.1
- Removed `with_observers` from `Executor` trait.
- `MmapShMemProvider::new_shmem_persistent` has been removed in favour of `MmapShMem::persist`. You probably want to do something like this: `let shmem = MmapShMemProvider::new()?.new_shmem(size)?.persist()?;`

# Pre 0.9 -> 0.9
- [Migrating from LibAFL <0.9 to 0.9](https://aflplus.plus/libafl-book/design/migration-0.9.html)