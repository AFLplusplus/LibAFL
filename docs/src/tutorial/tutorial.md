# LibAFL Tutorial: Your First Structure-Aware Fuzzer

Welcome to the LibAFL tutorial! In this guide, we'll walk you through building a structure-aware fuzzer for a simple C program. Structure-aware fuzzing is a powerful technique that can be much more effective than traditional fuzzing when the input format is well-defined.

We'll be using the `lain` crate for structure-aware mutations.

## The Target

Our target is a simple C program that processes packets. The code is in `fuzzers/baby/tutorial/target.c`:

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

To fuzz this target effectively, we need to define the input structure in Rust. This is done in `fuzzers/baby/tutorial/src/input.rs`:

```rust
#![allow(unexpected_cfgs)] // deriving NewFuzzed etc. introduces these
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

Now let's look at the fuzzer itself in `fuzzers/baby/tutorial/src/lib.rs`.

### The `libafl_main` function

The `libafl_main` function is the entry point of our fuzzer.

```rust
#[cfg(not(test))]
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
```

We use a `HitcountsMapObserver` to get code coverage, and a `TimeObserver` to measure execution time. These are used by `MaxMapFeedback` and `TimeFeedback` respectively. We also have a custom `PacketLenFeedback` which we'll look at later.

`CrashFeedback` and `TimeoutFeedback` are used to identify crashing or timing-out inputs.

```rust
// A minimization+queue policy to get testcasess from the corpus
let scheduler = PacketLenMinimizerScheduler::new(
    &edges_observer,
    PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
);
```

We use a `PowerQueueScheduler` to select the next input to fuzz. We wrap it in a custom `PacketLenMinimizerScheduler` to prioritize shorter inputs.

#### The Mutator

```rust
// Setup a lain mutator with a mutational stage
let mutator = LainMutator::new();

let power: StdPowerMutationalStage<_, _, PacketData, _, _, _> =
    StdPowerMutationalStage::new(mutator);

let mut stages = tuple_list!(calibration, power);
```

We use a custom `LainMutator` which is a wrapper around `lain`'s mutator. This is where the structure-aware magic happens. The `LainMutator` knows how to mutate the `PacketData` struct in a meaningful way.

### Custom Components

#### `PacketLenFeedback` and `PacketLenMinimizerScheduler`

These are defined in `fuzzers/baby/tutorial/src/metadata.rs`.

```rust
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
    cargo fuzz run
    ```

    The fuzzer will start, and you should see output like this:

    ```
    ...
    [2025-11-11T12:34:56Z INFO  libafl::events] New Testcase: 0, id: 0, exec_time: 10ms, op: Init
    ...
    ```

    Eventually, the fuzzer will find the crash and save the crashing input in the `crashes` directory.

## Conclusion

In this tutorial, we've built a structure-aware fuzzer using LibAFL and `lain`. We've seen how to define a custom input structure, use a structure-aware mutator, and customize the fuzzer with custom feedbacks and schedulers.

This is just a starting point. LibAFL is a very flexible framework that allows you to customize every aspect of the fuzzing process. We encourage you to explore the examples and the documentation to learn more.
