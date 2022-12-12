//! Based on <https://github.com/alecmocatta/build_id>
//! (C) Alec Mocatta <alec@mocatta.net> under license MIT or Apache 2

use std::{
    any::TypeId,
    env,
    fs::File,
    hash::{Hash, Hasher},
    io,
};

use once_cell::sync::Lazy;
use uuid::Uuid;

static BUILD_ID: Lazy<Uuid> = Lazy::new(calculate);

/// Returns a [Uuid] uniquely representing the build of the current binary.
///
/// This is intended to be used to check that different processes are indeed
/// invocations of identically laid out binaries.
///
/// As such:
/// * It is guaranteed to be identical within multiple invocations of the same
/// binary.
/// * It is guaranteed to be different across binaries with different code or
/// data segments or layout.
/// * Equality is unspecified if the binaries have identical code and data
/// segments and layout but differ immaterially (e.g. if a timestamp is included
/// in the binary at compile time).
///
/// # Examples
///
/// ```
/// # let remote_build_id = libafl::bolts::build_id::get();
/// let local_build_id = libafl::bolts::build_id::get();
/// if local_build_id == remote_build_id {
///     println!("We're running the same binary as remote!");
/// } else {
///     println!("We're running a different binary to remote");
/// }
/// ```
///
/// # Note
///
/// This looks first for linker-inserted build ID / binary UUIDs (i.e.
/// `.note.gnu.build-id` on Linux; `LC_UUID` in Mach-O; etc), falling back to
/// hashing the whole binary.
#[inline]
#[must_use]
pub fn get() -> Uuid {
    *BUILD_ID
}

fn from_exe<H: Hasher>(mut hasher: H) -> Result<H, ()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if cfg!(miri) {
            return Err(());
        }
        let file = File::open(env::current_exe().map_err(drop)?).map_err(drop)?;
        let _ = io::copy(&mut &file, &mut HashWriter(&mut hasher)).map_err(drop)?;
        Ok(hasher)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = &mut hasher;
        Err(())
    }
}
fn from_type_id<H: Hasher>(mut hasher: H) -> H {
    fn type_id_of<T: 'static>(_: &T) -> TypeId {
        TypeId::of::<T>()
    }
    TypeId::of::<()>().hash(&mut hasher);
    TypeId::of::<u8>().hash(&mut hasher);
    let a = |x: ()| x;
    type_id_of(&a).hash(&mut hasher);
    let b = |x: u8| x;
    type_id_of(&b).hash(&mut hasher);
    hasher
}

fn calculate() -> Uuid {
    let hasher = xxhash_rust::xxh3::Xxh3::with_seed(0);

    let hasher = from_exe(hasher.clone()).unwrap_or(hasher);
    let mut hasher = from_type_id(hasher);

    let mut bytes = [0; 16];
    <byteorder::NativeEndian as byteorder::ByteOrder>::write_u64(&mut bytes[..8], hasher.finish());
    hasher.write_u8(0);
    <byteorder::NativeEndian as byteorder::ByteOrder>::write_u64(&mut bytes[8..], hasher.finish());

    *uuid::Builder::from_bytes(bytes)
        .set_variant(uuid::Variant::RFC4122)
        .set_version(uuid::Version::Random)
        .as_uuid()
}

struct HashWriter<T: Hasher>(T);
impl<T: Hasher> io::Write for HashWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).map(|_| ())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
