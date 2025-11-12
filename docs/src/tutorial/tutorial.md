# `LibAFL` Custom Input Tutorial: Your Own Structure-Aware Fuzzer

Welcome to the `LibAFL` custom inputs tutorial! In this guide, we'll walk you through building a structure-aware fuzzer for a simple C program using a third-party grammar mutator.

We'll be using the `lain` crate for structure-aware mutations and hook it up to `LibAFL`. This could be done with any sort of mutator and input types, even if they are written in other programming languages.

## The Target

Our target is a simple C program that processes packets. The code can be found in [`fuzzers/baby/tutorial/target.c`](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/baby/tutorial/target.c):

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define MAX_PACKET_SIZE 0x1000

typedef enum _packet_type {
  data_read = 0x0,
  data_write = 0x1,
  data_reset = 0x2,
} packet_type;

#pragma pack(1)
typedef struct _packet_data {
  packet_type type;
  uint64_t    offset;
  uint64_t    length;
  char        data[0];
} packet_data;

int LLVMFuzzerTestOneInput(const uint8_t *packet_buffer, size_t packet_length) {
  ssize_t      saved_data_length = 0;
  char        *saved_data = NULL;
  int          err = 0;
  packet_data *datagram = NULL;

  if (packet_length < sizeof(packet_data) || packet_length > MAX_PACKET_SIZE) {
    return 1;
  }

  datagram = (packet_data *)packet_buffer;

  switch (datagram->type) {
    case data_read:
      if (saved_data != NULL &&
          datagram->offset + datagram->length <= saved_data_length) {
        write(0, packet_buffer + datagram->offset, datagram->length);
      }
      break;

    case data_write:
      // NOTE: Who cares about checking the offset? Nobody would ever provide
      // bad data
      if (saved_data != NULL && datagram->length <= saved_data_length) {
        memcpy(saved_data + datagram->offset, datagram->data, datagram->length);
      }
      break;

    case data_reset:
      if (datagram->length > packet_length - sizeof(*datagram)) { return 1; }

      if (saved_data != NULL) { free(saved_data); }

      saved_data = malloc(datagram->length);
      saved_data_length = datagram->length;

      memcpy(saved_data, datagram->data, datagram->length);
      break;

    default:
      return 1;
  }

  return 0;
}
```

The target defines a `LLVMFuzzerTestOneInput` function, which is the standard entry point for libFuzzer-style harnesses. It processes a `packet_data` structure. There's a vulnerability in the `data_write` case: it doesn't check the `offset`, which can lead to a heap buffer overflow.

## The Input

To fuzz this target effectively, we need to define the input structure in Rust. This is done in [`fuzzers/baby/tutorial/src/input.rs`](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/baby/tutorial/src/input.rs):

```rust
# extern crate lain;
# extern crate libafl;
# extern crate libafl_bolts;
# extern crate serde;
use std::hash::Hash;

use lain::prelude::*;
use libafl::inputs::{HasTargetBytes, Input};
use libafl_bolts::{ownedref::OwnedSlice, HasLen};
use serde::{Deserialize, Serialize};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Default,
    Clone,
    NewFuzzed,
    Mutatable,
    VariableSizeObject,
    BinarySerialize,
)]
pub struct PacketData {
    pub typ: UnsafeEnum<PacketType, u32>,

    pub offset: u64,
    pub length: u64,

    #[lain(max = 10)]
    pub data: Vec<u8>,
}

impl Fixup for PacketData {
    fn fixup<R: Rng>(&mut self, _mutator: &mut Mutator<R>) {
        self.length = self.data.len() as u64;
    }
}

#[derive(
    Serialize, Deserialize, Debug, Copy, Clone, FuzzerObject, ToPrimitiveU32, BinarySerialize, Hash,
)]
#[repr(u32)]
#[derive(Default)]
pub enum PacketType {
    #[default]
    Read = 0x0,
    Write = 0x1,
    Reset = 0x2,
}

impl Input for PacketData {}

impl HasTargetBytes for PacketData {
    #[inline]
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        let mut serialized_data = Vec::with_capacity(self.serialized_size());
        self.binary_serialize::<_, LittleEndian>(&mut serialized_data);
        OwnedSlice::from(serialized_data)
    }
}

impl HasLen for PacketData {
    fn len(&self) -> usize {
        self.serialized_size()
    }
}

impl Hash for PacketData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.typ {
            UnsafeEnum::Invalid(a) => a.hash(state),
            UnsafeEnum::Valid(a) => a.hash(state),
        }
        self.offset.hash(state);
        self.length.hash(state);
        self.data.hash(state);
    }
}
```

We use the `lain` crate to derive `NewFuzzed`, `Mutatable`, and other traits. This allows `lain` to generate and mutate `PacketData` structs automatically. The `fixup` function is used to keep the `length` field consistent with the actual length of the `data` vector.

The `HasTargetBytes` trait is implemented to serialize the `PacketData` struct into a byte slice that can be passed to the C target.

## The Fuzzer

Now let's look at the fuzzer itself in [`fuzzers/baby/tutorial/src/lib.rs`](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/baby/tutorial/src/lib.rs).

### The `libafl_main` function

The `libafl_main` function is the entry point of our fuzzer.

```rust
# extern crate libafl;
# use std::path::PathBuf;
# use libafl::Error;
# fn fuzz(_corpus_dirs: &[PathBuf], _objective_dir: PathBuf, _broker_port: u16) -> Result<(), Error> { Ok(()) }
#[no_mangle]
pub extern "C" fn libafl_main() {
    // ...
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .expect("An error occurred while fuzzing");
}
```

It calls the `fuzz` function with the corpus and objective directories, and a broker port for multi-threaded fuzzing.

### The `fuzz` function

The `fuzz` function contains the main fuzzer logic.

#### The Harness

```rust
# extern crate libafl;
# extern crate libafl_bolts;
# extern crate serde;
#
# use libafl::executors::ExitKind;
# use libafl::inputs::HasTargetBytes;
# use libafl_bolts::ownedref::OwnedSlice;
# use libafl_bolts::AsSlice;
#
# // Dummy PacketData
# #[derive(Debug)]
# pub struct PacketData {}
# impl HasTargetBytes for PacketData {
#     fn target_bytes(&self) -> OwnedSlice<u8> {
#         OwnedSlice::from(vec![])
#     }
# }
#
# // Dummy libfuzzer_test_one_input
# unsafe fn libfuzzer_test_one_input(_buf: &[u8]) {}
#
let mut harness = |input: &PacketData| {
    let target = input.target_bytes();
    let buf = target.as_slice();
    // # Safety
    // We're looking for crashes in there!
    unsafe {
        libfuzzer_test_one_input(buf);
    }
    ExitKind::Ok
};
```

The harness is a closure that takes a `PacketData` input, serializes it, and passes it to the `libfuzzer_test_one_input` function in our C target.

#### Observers, Feedbacks, and Scheduler

```rust
# use libafl::{
#     feedback_or, feedback_or_fast,
#     feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback, Feedback},
#     observers::{HitcountsMapObserver, TimeObserver, Observer, CanTrack},
#     stages::calibrate::CalibrationStage,
#     Error,
# };
# use libafl_bolts::{Named, MaybeOwned};
# use libafl_targets::std_edges_map_observer;
# use std::borrow::Cow;
#
# #[derive(Default, Debug)]
# struct PacketLenFeedback;
# impl PacketLenFeedback { fn new() -> Self { Self {} } }
# impl<EM, I, OT, S> Feedback<EM, I, OT, S> for PacketLenFeedback {
#     fn is_interesting(&mut self, _state: &mut S, _manager: &mut EM, _input: &I, _observers: &OT, _exit_kind: &libafl::executors::ExitKind) -> Result<bool, Error> { Ok(false) }
# }
# impl Named for PacketLenFeedback {
#     fn name(&self) -> &Cow<'static, str> {
#         static NAME: Cow<'static, str> = Cow::Borrowed("PacketLenFeedback");
#         &NAME
#     }
# }
#
# fn dummy_func() {
// Create an observation channel using the coverage map
let edges_observer =
    HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

// Create an observation channel to keep track of the execution time
let time_observer = TimeObserver::new("time");

let map_feedback = MaxMapFeedback::new(&edges_observer);

let calibration = CalibrationStage::new(&map_feedback);

// Feedback to rate the interestingness of an input
let mut feedback = feedback_or!(
    map_feedback,
    TimeFeedback::new(&time_observer),
    PacketLenFeedback::new()
);

// A feedback to choose if an input is a solution or not
let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
# }
```

We use a `HitcountsMapObserver` to get code coverage, and a `TimeObserver` to measure execution time. These are used by `MaxMapFeedback` and `TimeFeedback` respectively. We also have a custom `PacketLenFeedback` which we'll look at later.

`CrashFeedback` and `TimeoutFeedback` are used to identify crashing or timing-out inputs.

```rust
# extern crate libafl;
# extern crate libafl_bolts;
# extern crate libafl_targets;
# extern crate serde;
# fn dummy() -> Result<(), libafl::Error> {
# use libafl::{
#     observers::{HitcountsMapObserver, CanTrack},
#     schedulers::{powersched::PowerSchedule, PowerQueueScheduler},
#     state::StdState,
#     corpus::{InMemoryCorpus, OnDiskCorpus},
#     feedbacks::MaxMapFeedback,
#     Error,
# };
# use libafl_bolts::rands::StdRand;
# use libafl_targets::std_edges_map_observer;
#
# struct PacketLenMinimizerScheduler;
# impl PacketLenMinimizerScheduler {
#     fn new<O, S>(_observer: &O, _scheduler: S) -> Self { Self }
# }
#
# let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();
# let map_feedback = MaxMapFeedback::new(&edges_observer);
# let mut feedback = (map_feedback,);
# let mut objective = ();
# let mut state = StdState::new(
#     StdRand::new(),
#     InMemoryCorpus::new(),
#     OnDiskCorpus::new("./crashes")?,
#     &mut feedback,
#     &mut objective,
# )?;
#
// A minimization+queue policy to get testcasess from the corpus
let scheduler = PacketLenMinimizerScheduler::new(
    &edges_observer,
    PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
);
# Ok(())
# }
```

We use a `PowerQueueScheduler` to select the next input to fuzz. We wrap it in a custom `PacketLenMinimizerScheduler` to prioritize shorter inputs.

#### The Mutator

```rust
# fn dummy() {
# use libafl::{
#     stages::{power::StdPowerMutationalStage, Stage},
#     mutators::{MutationResult, Mutator},
#     state::HasRand,
#     Error,
# };
# use libafl_bolts::{tuples::tuple_list, rands::StdRand};
# use lain::prelude::{Mutatable, NewFuzzed, FuzzerObject, ToPrimitiveU32, BinarySerialize, VariableSizeObject, UnsafeEnum, Fixup, Rng};
# use serde::{Deserialize, Serialize};
# use std::vec::Vec;
#
# #[derive(Serialize, Deserialize, Debug, Default, Clone, NewFuzzed, Mutatable, VariableSizeObject, BinarySerialize)]
# pub struct PacketData {
#     pub typ: UnsafeEnum<PacketType, u32>,
#     pub offset: u64,
#     pub length: u64,
#     #[lain(max = 10)]
#     pub data: Vec<u8>,
# }
# impl Fixup for PacketData {
#     fn fixup<R: Rng>(&mut self, _mutator: &mut lain::mutator::Mutator<R>) { self.length = self.data.len() as u64; }
# }
# #[derive(Serialize, Deserialize, Debug, Copy, Clone, FuzzerObject, ToPrimitiveU32, BinarySerialize, std::hash::Hash)]
# #[repr(u32)]
# #[derive(Default)]
# pub enum PacketType { #[default] Read = 0x0, Write = 0x1, Reset = 0x2, }
#
# pub struct LainMutator;
# impl LainMutator { fn new() -> Self { Self } }
# impl<I, S> Mutator<I, S> for LainMutator where I: Mutatable, S: HasRand {
#     fn mutate(&mut self, _state: &mut S, _input: &mut I) -> Result<MutationResult, Error> { Ok(MutationResult::Mutated) }
# }
#
# struct DummyStage;
# impl<S> Stage<S> for DummyStage {
#     fn perform(
#         &mut self,
#         _fuzzer: &mut dyn libafl::fuzzer::HasCorpus<S>,
#         _executor: &mut dyn libafl::executors::HasObservers<S>,
#         _state: &mut S,
#         _manager: &mut dyn libafl::events::EventManager<S>,
#     ) -> Result<(), Error> {
#         Ok(())
#     }
# }
# let calibration = DummyStage;
#
// Setup a lain mutator with a mutational stage
let mutator = LainMutator::new();

let power: StdPowerMutationalStage<_, _, PacketData, _, _, _> =
    StdPowerMutationalStage::new(mutator);

let mut stages = tuple_list!(calibration, power);
# }
```

We use a custom `LainMutator` which is a wrapper around `lain`'s mutator. This is where the structure-aware magic happens. The `LainMutator` knows how to mutate the `PacketData` struct in a meaningful way.

### Custom Components

#### `PacketLenFeedback` and `PacketLenMinimizerScheduler`

These are defined in `fuzzers/baby/tutorial/src/metadata.rs`.

```rust
# extern crate libafl_bolts;
# extern crate serde;
# use serde::{Deserialize, Serialize};
# use libafl_bolts::SerdeAny;
# use std::fmt::Debug;
#
# trait Feedback<EM, I, OT, S> {
#     fn is_interesting(&mut self, state: &mut S, manager: &mut EM, input: &I, observers: &OT, exit_kind: &ExitKind) -> Result<bool, Error>;
#     fn append_metadata(&mut self, state: &mut S, manager: &mut EM, observers: &OT, testcase: &mut Testcase<I>) -> Result<(), Error>;
# }
# #[derive(Debug)]
# struct PacketData { length: u64 }
# #[derive(Debug)]
# struct PacketLenFeedback { len: u64 }
# #[derive(Debug)]
# struct ExitKind;
# #[derive(Debug)]
# struct Error;
# #[derive(Debug)]
# struct Testcase<I> { _phantom: std::marker::PhantomData<I> }
# impl<I> Testcase<I> {
#     fn metadata_map_mut(&mut self) -> &mut Self { self }
#     fn insert<T: SerdeAny>(&mut self, _meta: T) {}
# }
#
#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct PacketLenMetadata {
    pub length: u64,
}

// ...

impl<EM, OT, S> Feedback<EM, PacketData, OT, S> for PacketLenFeedback {
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &PacketData,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        self.len = input.length;
        Ok(false)
    }

    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<PacketData>,
    ) -> Result<(), Error> {
        testcase
            .metadata_map_mut()
            .insert(PacketLenMetadata { length: self.len });
        Ok(())
    }
}
```

The `PacketLenFeedback` doesn't mark any input as interesting, but it attaches the packet length as metadata to each testcase. The `PacketLenMinimizerScheduler` then uses this metadata to prioritize shorter inputs.

#### `LainMutator`

This is defined in `fuzzers/baby/tutorial/src/mutator.rs`.

```rust
# use std::fmt::Debug;
#
# mod lain {
#     #[derive(Debug)]
#     pub mod mutator { pub struct Mutator<R> { _phantom: std::marker::PhantomData<R> } }
# }
# impl<R> lain::mutator::Mutator<R> {
#     pub fn rng_mut(&mut self) -> &mut Self { self }
#     pub fn set_seed(&mut self, _seed: u64) {}
# }
#
# trait Mutator<I, S> {
#     fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error>;
# }
# trait HasRand {
#     fn rand_mut(&mut self) -> &mut Self;
# }
#
# trait Rand {
#     fn next(&mut self) -> u64;
# }
#
# impl<T: Rand> HasRand for T {
#     fn rand_mut(&mut self) -> &mut Self {
#         self
#     }
# }
#
# impl Rand for () {
#     fn next(&mut self) -> u64 { 0 }
# }
#
# #[derive(Debug)]
# struct StdRand;
# #[derive(Debug)]
# struct PacketData;
# impl PacketData {
#     fn mutate(&mut self, _m: &mut lain::mutator::Mutator<StdRand>, _s: Option<()>) {}
# }
# #[derive(Debug)]
# enum MutationResult { Mutated }
# #[derive(Debug)]
# struct Error;
#
pub struct LainMutator {
    inner: lain::mutator::Mutator<StdRand>,
}

impl<S> Mutator<PacketData, S> for LainMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PacketData) -> Result<MutationResult, Error> {
        // Lain uses its own instance of StdRand, but we want to keep it in sync with LibAFL's state.
        self.inner.rng_mut().set_seed(state.rand_mut().next());
        input.mutate(&mut self.inner, None);
        Ok(MutationResult::Mutated)
    }
    // ...
}
```

The `LainMutator` simply calls the `mutate` method on the `PacketData` input, which was derived using `lain`.

## Building and Running the Fuzzer

Now, let's build and run our fuzzer.

1. **Set the rust-toolchain**:
    The fuzzer uses nightly.

    ```sh
    cd fuzzers/baby/tutorial
    rustup override set nightly
    ```

2. **Build the fuzzer and the target**:
    We need to build the fuzzer library, and the target C code. The build script `fuzzers/baby/tutorial/build.rs` handles building the target C code and linking it against our fuzzer library.

    First, we need to set up the compiler wrappers.

    ```sh
    cargo build --bin libafl_cc
    cargo build --bin libafl_cxx
    ```

    Then, we set the `CC` and `CXX` environment variables to point to our wrappers.

    ```sh
    export CC=$(pwd)/target/debug/libafl_cc
    export CXX=$(pwd)/target/debug/libafl_cxx
    ```

    Now, we can build the target.

    ```sh
    make -C ../../.. fuzzers/baby/tutorial/target
    ```

    This will create a `target` executable in the `fuzzers/baby/tutorial` directory.

3. **Run the fuzzer**:

    ```sh
    cargo fuzz run --release
    ```

    Eventually, after running for a short while, the fuzzer will find the crash and save the crashing input in the `crashes` directory.
    The baby fuzzer won't restart afterwards. This will need a Restating event manager, such as [`LlmpRestartingEventManager`](https://docs.rs/libafl/latest/libafl/events/llmp/restarting/struct.LlmpRestartingEventManager.html).

## Conclusion

In this tutorial, we've built a structure-aware fuzzer using LibAFL and `lain`. We've seen how to define a custom input structure, use a structure-aware mutator, and customize the fuzzer with custom feedbacks and schedulers.

This is just a starting point. LibAFL is a very flexible framework that allows you to customize every aspect of the fuzzing process. We encourage you to explore the examples and the documentation to learn more.
