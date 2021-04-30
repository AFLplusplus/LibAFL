# Definition

A metadata in LibAFL is a self contained structure that holds associated data to the State or to a Testcase.

In terms of code, a metadata can be defined as a Rust struct registered in the SerdeAny register.

```rust
use libafl::SerdeAny;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, SerdeAny)]
pub struct MyMetadata {
    ...
}
```

The struct must be static, so it cannot hold references to borrowed objects.


