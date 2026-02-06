# Git Recency Scheduler

LibAFL can keep classic coverage-guided fuzzing, while also biasing scheduling toward inputs that execute **recently changed lines** (based on `git blame`).

This is opt-in:
- build-time: generate a `pcguard_index -> git blame timestamp` mapping file
- runtime: load the mapping into the state and use `GitAwareStdWeightedScheduler`

## Build-time mapping generation (C/C++)

Build the compiler wrappers with git-recency support:

```sh
cargo build --release --manifest-path fuzzers/forkserver/forkserver_libafl_cc/Cargo.toml --features git-recency --bins
```

Then, from inside the target project's git repository, build it using the wrappers and set the mapping output path:

```sh
export CC=/path/to/target/release/libafl_cc
export CXX=/path/to/target/release/libafl_cxx
export LIBAFL_GIT_RECENCY_MAPPING_PATH=$PWD/git_recency_map.bin

# Build with pc-guard coverage + debug info (exact flags depend on your build system)
make CFLAGS="-g" CXXFLAGS="-g"
```

Requirements:
- `-fsanitize-coverage=trace-pc-guard`
- debug info (for `file:line` mapping)
- `git` available; only files inside the repo root are blamed

## Using the scheduler

Enable index tracking on your map observer (`.track_indices()`), load the mapping, and use the git-aware weighted scheduler:

```rust,ignore
let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") })
    .track_indices();

state.add_metadata(GitRecencyMapMetadata::load_from_file("git_recency_map.bin")?);
state.add_metadata(GitRecencyConfigMetadata::new(2.0)); // optional (default is 2.0)

let scheduler = GitAwareStdWeightedScheduler::new(&mut state, &edges_observer);
```

The score caches `tc_time = max(blame_time[idx])` over all indices a testcase covers (from `MapIndexesMetadata`) and boosts the base corpus weight by `1 + alpha * decay`, using an exponential decay (fixed 14-day half-life) relative to the `HEAD` commit time stored in the mapping file.

## Mapping format

The mapping file is little-endian:
- `u64 head_time`
- `u64 len`
- `len * u64 entries`
