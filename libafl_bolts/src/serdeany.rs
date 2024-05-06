//! Poor-rust-man's downcasts for stuff we send over the wire (or shared maps)

use alloc::boxed::Box;
#[cfg(feature = "unsafe_stable_anymap")]
use alloc::string::{String, ToString};
#[cfg(feature = "unsafe_stable_anymap")]
use core::any::type_name;
#[cfg(not(feature = "unsafe_stable_anymap"))]
use core::any::TypeId;
use core::{any::Any, fmt::Debug};

use serde::{de::DeserializeSeed, Deserialize, Deserializer, Serialize, Serializer};
pub use serdeany_registry::*;

#[cfg(not(feature = "unsafe_stable_anymap"))]
use crate::anymap::unpack_type_id;

/// The type of a stored type in this anymap (`u128`)
#[cfg(not(feature = "unsafe_stable_anymap"))]
pub type TypeRepr = u128;

/// The type of a stored type in this anymap (`String`)
#[cfg(feature = "unsafe_stable_anymap")]
pub type TypeRepr = String;

#[cfg(not(feature = "unsafe_stable_anymap"))]
fn type_repr<T>() -> TypeRepr
where
    T: 'static,
{
    unpack_type_id(TypeId::of::<T>())
}

#[cfg(not(feature = "unsafe_stable_anymap"))]
fn type_repr_owned<T>() -> TypeRepr
where
    T: 'static,
{
    unpack_type_id(TypeId::of::<T>())
}

#[cfg(feature = "unsafe_stable_anymap")]
fn type_repr_owned<T>() -> TypeRepr {
    type_name::<T>().to_string()
}

#[cfg(feature = "unsafe_stable_anymap")]
fn type_repr<T>() -> &'static str {
    type_name::<T>()
}

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
pub mod serdeany_registry {

    use alloc::{
        boxed::Box,
        string::{String, ToString},
    };
    use core::{any::TypeId, fmt, hash::BuildHasherDefault};

    use hashbrown::{
        hash_map::{Values, ValuesMut},
        HashMap,
    };
    use serde::{Deserialize, Serialize};

    use crate::{
        serdeany::{
            type_repr, type_repr_owned, DeserializeCallback, DeserializeCallbackSeed, SerdeAny,
            TypeRepr,
        },
        Error,
    };

    /// A [`HashMap`] that maps from [`TypeRepr`] to a deserializer and its [`TypeId`].
    type DeserializeCallbackMap = HashMap<TypeRepr, (DeserializeCallback<dyn SerdeAny>, TypeId)>;

    /// Visitor object used internally for the [`crate::serdeany::SerdeAny`] registry.
    #[derive(Debug)]
    pub struct BoxDynVisitor {}
    #[allow(unused_qualifications)]
    impl<'de> serde::de::Visitor<'de> for BoxDynVisitor {
        type Value = Box<dyn crate::serdeany::SerdeAny>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Expecting a serialized trait object")
        }

        fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let id: TypeRepr = visitor.next_element()?.unwrap();
            let cb = unsafe {
                REGISTRY
                    .deserializers
                    .as_ref()
                    .expect("Empty types registry")
                    .get(&id)
                    .expect("Cannot deserialize an unregistered type")
                    .0
            };
            let seed = DeserializeCallbackSeed::<dyn crate::serdeany::SerdeAny> { cb };
            let obj: Self::Value = visitor.next_element_seed(seed)?.unwrap();
            Ok(obj)
        }
    }

    #[allow(unused_qualifications)]
    struct Registry {
        deserializers: Option<DeserializeCallbackMap>,
        finalized: bool,
    }

    #[allow(unused_qualifications)]
    impl Registry {
        pub fn register<T>(&mut self)
        where
            T: crate::serdeany::SerdeAny + Serialize + serde::de::DeserializeOwned,
        {
            assert!(!self.finalized, "Registry is already finalized!");

            let deserializers = self.deserializers.get_or_insert_with(HashMap::default);
            let _entry = deserializers
                .entry(type_repr_owned::<T>())
                .or_insert_with(|| {
                    (
                        |de| Ok(Box::new(erased_serde::deserialize::<T>(de)?)),
                        TypeId::of::<T>(),
                    )
                });

            #[cfg(feature = "unsafe_stable_anymap")]
            assert_eq!(_entry.1, TypeId::of::<T>(), "Fatal safety error: TypeId of type {} is not equals to the deserializer's TypeId for this type! Two registered types have the same type_name!", type_repr::<T>());
        }

        pub fn finalize(&mut self) {
            self.finalized = true;
        }
    }

    static mut REGISTRY: Registry = Registry {
        deserializers: None,
        finalized: false,
    };

    /// This sugar must be used to register all the structs which
    /// have trait objects that can be serialized and deserialized in the program
    #[derive(Debug)]
    pub struct RegistryBuilder {}

    #[allow(unused_qualifications)]
    impl RegistryBuilder {
        /// Register a given struct type for trait object (de)serialization
        ///
        /// # Safety
        /// This may never be called concurrently or at the same time as `finalize`.
        /// It dereferences the `REGISTRY` hashmap and adds the given type to it.
        pub unsafe fn register<T>()
        where
            T: crate::serdeany::SerdeAny + Serialize + serde::de::DeserializeOwned,
        {
            unsafe {
                REGISTRY.register::<T>();
            }
        }

        /// Finalize the registry, no more registrations are allowed after this call
        ///
        /// # Safety
        /// This may never be called concurrently or at the same time as `register`.
        /// It dereferences the `REGISTRY` hashmap and adds the given type to it.
        pub fn finalize() {
            unsafe {
                REGISTRY.finalize();
            }
        }
    }

    /// A (de)serializable anymap containing (de)serializable trait objects registered
    /// in the registry
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SerdeAnyMap {
        map: HashMap<TypeRepr, Box<dyn SerdeAny>>,
    }

    // Cloning by serializing and deserializing. It ain't fast, but it's honest work.
    // We unwrap postcard, it should not have a reason to fail.
    impl Clone for SerdeAnyMap {
        fn clone(&self) -> Self {
            let serialized = postcard::to_allocvec(&self).unwrap();
            postcard::from_bytes(&serialized).unwrap()
        }
    }

    /*
    #[cfg(feature = "anymap_debug")]
    impl fmt::Debug for SerdeAnyMap {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let json = serde_json::to_string(&self);
            write!(f, "SerdeAnyMap: [{:?}]", json)
        }
    }

    #[cfg(not(feature = "anymap_debug"))]
    impl fmt::Debug for SerdeAnyMap {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "SerdeAnymap with {} elements", self.len())
        }
    }*/

    #[allow(unused_qualifications)]
    impl SerdeAnyMap {
        /// Get an element from the map.
        #[must_use]
        #[inline]
        pub fn get<T>(&self) -> Option<&T>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            self.map
                .get(type_repr)
                .map(|x| x.as_ref().as_any().downcast_ref::<T>().unwrap())
        }

        /// Get a mutable borrow for an element in the map.
        #[must_use]
        #[inline]
        pub fn get_mut<T>(&mut self) -> Option<&mut T>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            self.map
                .get_mut(type_repr)
                .map(|x| x.as_mut().as_any_mut().downcast_mut::<T>().unwrap())
        }

        /// Remove an element in the map. Returns the removed element.
        #[must_use]
        #[inline]
        pub fn remove<T>(&mut self) -> Option<Box<T>>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            self.map
                .remove(type_repr)
                .map(|x| x.as_any_boxed().downcast::<T>().unwrap())
        }

        /// Insert an element into the map.
        #[inline]
        pub fn insert<T>(&mut self, t: T)
        where
            T: crate::serdeany::SerdeAny,
        {
            self.insert_boxed(Box::new(t));
        }

        /// Insert a boxed element into the map.
        #[inline]
        pub fn insert_boxed<T>(&mut self, value: Box<T>)
        where
            T: crate::serdeany::SerdeAny,
        {
            self.raw_entry_mut::<T>()
                .insert(type_repr_owned::<T>(), value);
        }

        /// Get an entry to an element in this map.
        #[inline]
        #[allow(unused_qualifications)]
        pub fn raw_entry_mut<T>(
            &mut self,
        ) -> hashbrown::hash_map::RawEntryMut<
            '_,
            TypeRepr,
            Box<dyn SerdeAny + 'static>,
            BuildHasherDefault<ahash::AHasher>,
        >
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            assert!(
                        unsafe {
                            REGISTRY
                                .deserializers
                                .as_ref()
                                .expect("Empty types registry")
                                .get(type_repr)
                                .is_some()
                        },
                        "Type {} was inserted without registration! Call RegistryBuilder::register::<{}>() or use serde_autoreg.",
                        core::any::type_name::<T>(),
                        core::any::type_name::<T>()
                    );
            self.map.raw_entry_mut().from_key(type_repr)
        }

        /// Gets a value by type, or inserts it using the given construction function `default`
        pub fn get_or_insert_with<T>(&mut self, default: impl FnOnce() -> T) -> &mut T
        where
            T: SerdeAny,
        {
            self.get_or_insert_with_boxed::<T>(|| Box::new(default()))
        }

        /// Gets a value by type, or inserts it using the given construction function `default` (returning a boxed value)
        pub fn get_or_insert_with_boxed<T>(&mut self, default: impl FnOnce() -> Box<T>) -> &mut T
        where
            T: SerdeAny + 'static,
        {
            let ret = self
                .raw_entry_mut::<T>()
                .or_insert_with(|| (type_repr_owned::<T>(), default()));
            ret.1.as_any_mut().downcast_mut::<T>().unwrap()
        }

        /// Returns the count of elements in this map.
        #[must_use]
        #[inline]
        pub fn len(&self) -> usize {
            self.map.len()
        }

        /// Returns `true` if this map is empty.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.map.is_empty()
        }

        /// Returns if the map contains the given type.
        #[must_use]
        #[inline]
        pub fn contains<T>(&self) -> bool
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            self.map.contains_key(type_repr)
        }

        /// Create a new [`SerdeAnyMap`].
        #[must_use]
        pub fn new() -> Self {
            SerdeAnyMap {
                map: HashMap::default(),
            }
        }
    }

    impl Default for SerdeAnyMap {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A serializable [`HashMap`] wrapper for [`crate::serdeany::SerdeAny`] types, addressable by name.
    #[allow(clippy::unsafe_derive_deserialize)]
    #[allow(unused_qualifications)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct NamedSerdeAnyMap {
        map: HashMap<TypeRepr, HashMap<String, Box<dyn crate::serdeany::SerdeAny>>>,
    }

    // Cloning by serializing and deserializing. It ain't fast, but it's honest work.
    // We unwrap postcard, it should not have a reason to fail.
    impl Clone for NamedSerdeAnyMap {
        fn clone(&self) -> Self {
            let serialized = postcard::to_allocvec(&self).unwrap();
            postcard::from_bytes(&serialized).unwrap()
        }
    }

    #[allow(unused_qualifications)]
    impl NamedSerdeAnyMap {
        /// Get an element by name
        #[must_use]
        #[inline]
        pub fn get<T>(&self, name: &str) -> Option<&T>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            match self.map.get(type_repr) {
                None => None,
                Some(h) => h.get(name).map(|x| x.as_any().downcast_ref::<T>().unwrap()),
            }
        }

        /// Remove an element by type and name
        #[must_use]
        #[inline]
        pub fn remove<T>(&mut self, name: &str) -> Option<Box<T>>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            match self.map.get_mut(type_repr) {
                None => None,
                Some(h) => h
                    .remove(name)
                    .map(|x| x.as_any_boxed().downcast::<T>().unwrap()),
            }
        }

        /// Get an element of a given type contained in this map by type `T`, as mut.
        #[must_use]
        #[inline]
        pub fn get_mut<T>(&mut self, name: &str) -> Option<&mut T>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            match self.map.get_mut(type_repr) {
                None => None,
                Some(h) => h
                    .get_mut(name)
                    .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
            }
        }

        /// Get all elements of a type contained in this map.
        #[must_use]
        #[allow(unused_qualifications)]
        #[inline]
        #[allow(clippy::type_complexity)]
        pub fn get_all<T>(
            &self,
        ) -> Option<
            core::iter::Map<
                Values<'_, String, Box<dyn crate::serdeany::SerdeAny>>,
                fn(&Box<dyn crate::serdeany::SerdeAny>) -> &T,
            >,
        >
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            #[allow(clippy::manual_map)]
            match self.map.get(type_repr) {
                None => None,
                Some(h) => Some(h.values().map(|x| x.as_any().downcast_ref::<T>().unwrap())),
            }
        }

        /// Get all elements contained in this map, as mut.
        #[inline]
        #[allow(unused_qualifications)]
        #[allow(clippy::type_complexity)]
        pub fn get_all_mut<T>(
            &mut self,
        ) -> Option<
            core::iter::Map<
                ValuesMut<'_, String, Box<dyn crate::serdeany::SerdeAny>>,
                fn(&mut Box<dyn crate::serdeany::SerdeAny>) -> &mut T,
            >,
        >
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            #[allow(clippy::manual_map)]
            match self.map.get_mut(type_repr) {
                None => None,
                Some(h) => Some(
                    h.values_mut()
                        .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
                ),
            }
        }

        /// Run `func` for each element in this map.
        #[inline]
        #[allow(unused_qualifications)]
        pub fn for_each<
            F: FnMut(&TypeRepr, &Box<dyn crate::serdeany::SerdeAny>) -> Result<(), Error>,
        >(
            &self,
            func: &mut F,
        ) -> Result<(), Error> {
            for (id, h) in &self.map {
                for x in h.values() {
                    func(id, x)?;
                }
            }
            Ok(())
        }

        /// Run `func` for each element in this map, getting a mutable borrow.
        #[inline]
        pub fn for_each_mut<
            F: FnMut(&TypeRepr, &mut Box<dyn crate::serdeany::SerdeAny>) -> Result<(), Error>,
        >(
            &mut self,
            func: &mut F,
        ) -> Result<(), Error> {
            for (id, h) in &mut self.map {
                for x in h.values_mut() {
                    func(id, x)?;
                }
            }
            Ok(())
        }

        /// Insert an element into this map.
        #[inline]
        #[allow(unused_qualifications)]
        pub fn insert<T>(&mut self, name: &str, val: T)
        where
            T: crate::serdeany::SerdeAny,
        {
            self.entry::<T>(name.into()).insert(Box::new(val));
        }

        /// Get a reference to the type map.
        #[inline]
        #[allow(unused_qualifications)]
        fn outer_map_mut<T>(
            &mut self,
        ) -> &mut hashbrown::hash_map::HashMap<String, Box<dyn SerdeAny + 'static>>
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            assert!(
                        unsafe {
                            REGISTRY
                                .deserializers
                                .as_ref()
                                .expect("Empty types registry")
                                .get(type_repr)
                                .is_some()
                        },
                        "Type {} was inserted without registration! Call RegistryBuilder::register::<{}>() or use serde_autoreg.",
                        core::any::type_name::<T>(),
                        core::any::type_name::<T>()
                    );
            self.map
                .raw_entry_mut()
                .from_key(type_repr)
                .or_insert_with(|| (type_repr_owned::<T>(), HashMap::default()))
                .1
        }

        /// Get an entry to an element into this map.
        /// Prefer [`Self::raw_entry_mut`] as it won't need an owned key.
        #[inline]
        #[allow(unused_qualifications)]
        fn entry<T>(
            &mut self,
            name: String,
        ) -> hashbrown::hash_map::Entry<
            '_,
            String,
            Box<dyn SerdeAny + 'static>,
            BuildHasherDefault<ahash::AHasher>,
        >
        where
            T: crate::serdeany::SerdeAny,
        {
            self.outer_map_mut::<T>().entry(name)
        }

        /// Get a raw entry to an element into this map.
        #[inline]
        #[allow(unused_qualifications)]
        fn raw_entry_mut<T>(
            &mut self,
            name: &str,
        ) -> hashbrown::hash_map::RawEntryMut<
            '_,
            String,
            Box<dyn SerdeAny + 'static>,
            BuildHasherDefault<ahash::AHasher>,
        >
        where
            T: crate::serdeany::SerdeAny,
        {
            self.outer_map_mut::<T>().raw_entry_mut().from_key(name)
        }

        /// Gets a value by name, or inserts it using the given construction function `default`
        pub fn get_or_insert_with<T>(&mut self, name: &str, default: impl FnOnce() -> T) -> &mut T
        where
            T: SerdeAny,
        {
            let ret = self
                .raw_entry_mut::<T>(name)
                .or_insert_with(|| (name.to_string(), Box::new(default())));
            ret.1.as_any_mut().downcast_mut::<T>().unwrap()
        }

        /// Gets a value by name, or inserts it using the given construction function `default` (returning a boxed value)
        pub fn get_or_insert_with_boxed<T>(
            &mut self,
            name: &str,
            default: impl FnOnce() -> Box<T>,
        ) -> &mut T
        where
            T: SerdeAny + 'static,
        {
            let ret = self
                .raw_entry_mut::<T>(name)
                .or_insert_with(|| (name.to_string(), default()));
            ret.1.as_any_mut().downcast_mut::<T>().unwrap()
        }

        /// Returns the `len` of this map.
        #[must_use]
        #[inline]
        pub fn len(&self) -> usize {
            self.map.len()
        }

        /// Returns `true` if this map is empty.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.map.is_empty()
        }

        /// Returns if the element with a given type is contained in this map.
        #[must_use]
        #[inline]
        pub fn contains_type<T>(&self) -> bool
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            self.map.contains_key(type_repr)
        }

        /// Returns if the element by a given `name` is contained in this map.
        #[must_use]
        #[inline]
        pub fn contains<T>(&self, name: &str) -> bool
        where
            T: crate::serdeany::SerdeAny,
        {
            let type_repr = type_repr::<T>();
            #[cfg(not(feature = "unsafe_stable_anymap"))]
            let type_repr = &type_repr;

            match self.map.get(type_repr) {
                None => false,
                Some(h) => h.contains_key(name),
            }
        }

        /// Create a new `SerdeAny` map.
        #[must_use]
        pub fn new() -> Self {
            Self {
                map: HashMap::default(),
            }
        }
    }

    impl Default for NamedSerdeAnyMap {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[allow(unused_qualifications)]
impl Serialize for dyn crate::serdeany::SerdeAny {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        let id = crate::anymap::unpack_type_id(self.type_id());
        let mut seq = se.serialize_seq(Some(2))?;
        seq.serialize_element(&id)?;
        seq.serialize_element(&crate::serdeany::Wrap(self))?;
        seq.end()
    }
}

#[allow(unused_qualifications)]
impl<'de> Deserialize<'de> for Box<dyn crate::serdeany::SerdeAny> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn crate::serdeany::SerdeAny>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(serdeany_registry::BoxDynVisitor {})
    }
}

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
    ($struct_name:ident < $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ > $(, < $( $opt:tt ),+ >)*) =>
    {
        impl < $( $lt $( : $clt $(+ $dlt )* )? ),+ >
            $crate::serdeany::SerdeAny
            for $struct_name < $( $lt ),+ >
        {
            fn as_any(&self) -> &dyn ::core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn ::core::any::Any {
                self
            }

            fn as_any_boxed(
                self: $crate::alloc::boxed::Box<$struct_name < $( $lt ),+ >>,
            ) -> $crate::alloc::boxed::Box<dyn ::core::any::Any> {
                self
            }
        }

        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        impl< $( $lt $( : $clt $(+ $dlt )* )? ),+ > $struct_name < $( $lt ),+ > {

            /// Manually register this type at a later point in time
            ///
            /// # Safety
            /// This may never be called concurrently as it dereferences the `RegistryBuilder` without acquiring a lock.
            pub unsafe fn register() {
                $crate::serdeany::RegistryBuilder::register::<$struct_name < $( $lt ),+ >>();
            }
        }

        $(
            $crate::create_register!($struct_name < $( $opt ),+ >);
        )*
    };
    ($struct_name:ident) =>
    {
        impl
            $crate::serdeany::SerdeAny
            for $struct_name
        {
            fn as_any(&self) -> &dyn ::core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn ::core::any::Any {
                self
            }

            fn as_any_boxed(
                self: $crate::alloc::boxed::Box<$struct_name>,
            ) -> $crate::alloc::boxed::Box<dyn ::core::any::Any> {
                self
            }
        }

        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        impl $struct_name {
            /// Manually register this type at a later point in time
            ///
            /// # Safety
            /// This may never be called concurrently as it dereferences the `RegistryBuilder` without acquiring a lock.
            #[allow(unused)]
            pub unsafe fn register() {
                $crate::serdeany::RegistryBuilder::register::<$struct_name>();
            }
        }

        $crate::create_register!($struct_name);
    };
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::serdeany::RegistryBuilder;

    #[derive(Debug, Serialize, Deserialize)]
    struct MyType(u32);
    impl_serdeany!(MyType);

    mod inner {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        pub(super) struct MyType(f32);
        impl_serdeany!(MyType);
    }

    #[test]
    fn test_deserialize_serialize() {
        unsafe {
            RegistryBuilder::register::<MyType>();
            RegistryBuilder::register::<inner::MyType>();
        }

        let val = MyType(1);
        let serialized = postcard::to_allocvec(&val).unwrap();

        assert_eq!(
            postcard::from_bytes::<MyType>(&serialized).unwrap().0,
            val.0
        );
        assert!(postcard::from_bytes::<inner::MyType>(&serialized).is_err());
    }
}
