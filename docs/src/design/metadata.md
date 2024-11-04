# Metadata

A metadata in LibAFL is a self-contained structure that holds associated data to the State or to a Testcase.

In terms of code, a metadata can be defined as a Rust struct registered in the SerdeAny register.

```rust
# extern crate libafl_bolts;
# extern crate serde;

use libafl_bolts::SerdeAny;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct MyMetadata {
    //...
}
```

The struct must be static, so it cannot hold references to borrowed objects.

As an alternative to `derive(SerdeAny)` which is a proc-macro in `libafl_derive` the user can use `libafl_bolts::impl_serdeany!(MyMetadata);`.

## Usage

Metadata objects are primarly intended to be used inside [`SerdeAnyMap`](https://docs.rs/libafl_bolts/latest/libafl_bolts/serdeany/serdeany_registry/struct.SerdeAnyMap.html) and [`NamedSerdeAnyMap`](https://docs.rs/libafl_bolts/latest/libafl_bolts/serdeany/serdeany_registry/struct.NamedSerdeAnyMap.html).

With these maps, the user can retrieve instances by type (and name). Internally, the instances are stored as SerdeAny trait objects.

Structs that want to have a set of metadata must implement the [`HasMetadata`](https://docs.rs/libafl/latest/libafl/common/trait.HasMetadata.html) trait.

By default, Testcase and State implement it and hold a SerdeAnyMap testcase.

## (De)Serialization

We are interested to store State's Metadata to not lose them in case of crash or stop of a fuzzer. To do that, they must be serialized and unserialized using Serde.

As Metadata is stored in a SerdeAnyMap as trait objects, they cannot be deserialized using Serde by default.

To cope with this problem, in LibAFL each SerdeAny struct must be registered in a global registry that keeps track of types and allows the (de)serialization of the registered types.

Normally, the `impl_serdeany` macro does that for the user creating a constructor function that fills the registry. However, when using LibAFL in no_std mode, this operation must be carried out manually before any other operation in the `main` function.

To do that, the developer needs to know each metadata type that is used inside the fuzzer and call `RegistryBuilder::register::<MyMetadata>()` for each of them at the beginning of `main`.
