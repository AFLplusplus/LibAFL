//! Poor-rust-man's downcasts for stuff we send over the wire (or shared maps)

use alloc::boxed::Box;
use core::{any::Any, fmt::Debug};

use serde::{de::DeserializeSeed, Deserialize, Deserializer, Serialize, Serializer};

/// A (de)serializable Any trait
pub trait SerdeAny: Any + erased_serde::Serialize + Debug {
    /// returns this as Any trait
    fn as_any(&self) -> &dyn Any;
    /// returns this as mutable Any trait
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// returns this as boxed Any trait
    fn as_any_boxed(self: Box<Self>) -> Box<dyn Any>;
}

/// Wrap a type for serialization
#[derive(Debug)]
pub struct Wrap<'a, T: ?Sized>(pub &'a T);

impl<'a, T> Serialize for Wrap<'a, T>
where
    T: ?Sized + erased_serde::Serialize + 'a,
{
    /// Serialize the type
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        erased_serde::serialize(self.0, serializer)
    }
}

/// Callback for [`SerdeAny`] deserialization.
pub type DeserializeCallback<B> =
    fn(&mut dyn erased_serde::Deserializer) -> Result<Box<B>, erased_serde::Error>;

/// Callback struct for deserialization of a [`SerdeAny`] type.
#[allow(missing_debug_implementations)]
pub struct DeserializeCallbackSeed<B>
where
    B: ?Sized,
{
    /// Callback for deserialization of a [`SerdeAny`] type.
    pub cb: DeserializeCallback<B>,
}

impl<'de, B> DeserializeSeed<'de> for DeserializeCallbackSeed<B>
where
    B: ?Sized,
{
    type Value = Box<B>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut erased = <dyn erased_serde::Deserializer>::erase(deserializer);
        (self.cb)(&mut erased).map_err(serde::de::Error::custom)
    }
}

/// Creates the [`serde`] registry for serialization and deserialization of [`SerdeAny`].
/// Each element needs to be registered so that it can be deserialized.
#[macro_export]
macro_rules! create_serde_registry_for_trait {
    ($($tt:tt)*) => {};
}

create_serde_registry_for_trait!(serdeany_registry, crate::serdeany::SerdeAny);
pub use serdeany_registry::*;

/// Register a `SerdeAny` type in the [`RegistryBuilder`]
///
/// Do nothing for without the `serdeany_autoreg` feature, you'll have to register it manually
/// in `main()` with [`RegistryBuilder::register`] or using `<T>::register()`.
#[cfg(all(feature = "serdeany_autoreg", not(miri)))]
#[macro_export]
macro_rules! create_register {
    ($struct_type:ty) => {
        const _: () = {
            /// Automatically register this type
            #[$crate::ctor]
            fn register() {
                // # Safety
                // This `register` call will always run at startup and never in parallel.
                unsafe {
                    $crate::serdeany::RegistryBuilder::register::<$struct_type>();
                }
            }
        };
    };
}

/// Register a `SerdeAny` type in the [`RegistryBuilder`]
///
/// Do nothing for without the `serdeany_autoreg` feature, you'll have to register it manually
/// in `main()` with [`RegistryBuilder::register`] or using `<T>::register()`.
#[cfg(not(all(feature = "serdeany_autoreg", not(miri))))]
#[macro_export]
macro_rules! create_register {
    ($struct_type:ty) => {};
}

/// Implement a [`SerdeAny`], registering it in the [`RegistryBuilder`] when on std
#[macro_export]
macro_rules! impl_serdeany {
    ($($tt:tt)*) => {};
}
