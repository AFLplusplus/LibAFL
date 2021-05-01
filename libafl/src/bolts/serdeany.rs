//! Poor-rust-man's downcasts for stuff we send over the wire (or shared maps)

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use alloc::boxed::Box;
use core::any::{Any, TypeId};

// yolo

pub fn pack_type_id(id: u64) -> TypeId {
    assert_eq_size!(TypeId, u64);
    unsafe { *(&id as *const u64 as *const TypeId) }
}

pub fn unpack_type_id(id: TypeId) -> u64 {
    assert_eq_size!(TypeId, u64);
    unsafe { *(&id as *const _ as *const u64) }
}

/// A (de)serializable Any trait
pub trait SerdeAny: Any + erased_serde::Serialize {
    /// returns this as Any trait
    fn as_any(&self) -> &dyn Any;
    /// returns this as mutable Any trait
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct Wrap<'a, T: ?Sized>(pub &'a T);
impl<'a, T> Serialize for Wrap<'a, T>
where
    T: ?Sized + erased_serde::Serialize + 'a,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        erased_serde::serialize(self.0, serializer)
    }
}

pub type DeserializeCallback<B> =
    fn(&mut dyn erased_serde::Deserializer) -> Result<Box<B>, erased_serde::Error>;

pub struct DeserializeCallbackSeed<B>
where
    B: ?Sized,
{
    pub cb: DeserializeCallback<B>,
}

impl<'de, B> serde::de::DeserializeSeed<'de> for DeserializeCallbackSeed<B>
where
    B: ?Sized,
{
    type Value = Box<B>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let mut erased = erased_serde::Deserializer::erase(deserializer);
        (self.cb)(&mut erased).map_err(serde::de::Error::custom)
    }
}

#[macro_export]
macro_rules! create_serde_registry_for_trait {
    ($mod_name:ident, $trait_name:path) => {
        pub mod $mod_name {

            use alloc::boxed::Box;
            use core::any::{Any, TypeId};
            use core::fmt;
            use postcard;
            use serde::{Deserialize, Serialize};

            use hashbrown::hash_map::{Keys, Values, ValuesMut};
            use hashbrown::HashMap;

            use $crate::bolts::serdeany::{
                pack_type_id, unpack_type_id, DeserializeCallback, DeserializeCallbackSeed,
            };
            use $crate::Error;

            pub struct BoxDynVisitor {}
            impl<'de> serde::de::Visitor<'de> for BoxDynVisitor {
                type Value = Box<dyn $trait_name>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("Expecting a serialized trait object")
                }

                fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::SeqAccess<'de>,
                {
                    let id: u64 = visitor.next_element()?.unwrap();
                    let cb = unsafe {
                        *REGISTRY
                            .deserializers
                            .as_ref()
                            .unwrap()
                            .get(&id)
                            .expect("Cannot deserialize an unregistered type")
                    };
                    let seed = DeserializeCallbackSeed::<dyn $trait_name> { cb };
                    let obj: Self::Value = visitor.next_element_seed(seed)?.unwrap();
                    Ok(obj)
                }
            }

            struct Registry {
                deserializers: Option<HashMap<u64, DeserializeCallback<dyn $trait_name>>>,
                finalized: bool,
            }

            impl Registry {
                pub fn register<T>(&mut self)
                where
                    T: $trait_name + Serialize + serde::de::DeserializeOwned,
                {
                    if self.finalized {
                        panic!("Registry is already finalized!");
                    }

                    let deserializers = self.deserializers.get_or_insert_with(HashMap::default);
                    deserializers.insert(unpack_type_id(TypeId::of::<T>()), |de| {
                        Ok(Box::new(erased_serde::deserialize::<T>(de)?))
                    });
                }

                pub fn finalize(&mut self) {
                    self.finalized = true;
                }
            }

            static mut REGISTRY: Registry = Registry {
                deserializers: None,
                finalized: false,
            };

            /// This shugar must be used to register all the structs which
            /// have trait objects that can be serialized and deserialized in the program
            pub struct RegistryBuilder {}

            impl RegistryBuilder {
                /// Register a given struct type for trait object (de)serialization
                pub fn register<T>()
                where
                    T: $trait_name + Serialize + serde::de::DeserializeOwned,
                {
                    unsafe {
                        REGISTRY.register::<T>();
                    }
                }

                /// Finalize the registry, no more registrations are allowed after this call
                pub fn finalize() {
                    unsafe {
                        REGISTRY.finalize();
                    }
                }
            }

            #[derive(Serialize, Deserialize)]
            /// A (de)serializable anymap containing (de)serializable trait objects registered
            /// in the registry
            pub struct SerdeAnyMap {
                map: HashMap<u64, Box<dyn $trait_name>>,
            }

            // Cloning by serializing and deserializing. It ain't fast, but it's honest work.
            // We unwrap postcard, it should not have a reason to fail.
            impl Clone for SerdeAnyMap {
                fn clone(&self) -> Self {
                    let serialized = postcard::to_allocvec(&self).unwrap();
                    postcard::from_bytes(&serialized).unwrap()
                }
            }

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
            }

            impl SerdeAnyMap {
                #[inline]
                pub fn get<T>(&self) -> Option<&T>
                where
                    T: $trait_name,
                {
                    self.map
                        .get(&unpack_type_id(TypeId::of::<T>()))
                        .map(|x| x.as_ref().as_any().downcast_ref::<T>().unwrap())
                }

                #[inline]
                pub fn get_mut<T>(&mut self) -> Option<&mut T>
                where
                    T: $trait_name,
                {
                    self.map
                        .get_mut(&unpack_type_id(TypeId::of::<T>()))
                        .map(|x| x.as_mut().as_any_mut().downcast_mut::<T>().unwrap())
                }

                #[inline]
                pub fn insert<T>(&mut self, t: T)
                where
                    T: $trait_name,
                {
                    self.map
                        .insert(unpack_type_id(TypeId::of::<T>()), Box::new(t));
                }

                #[inline]
                pub fn len(&self) -> usize {
                    self.map.len()
                }

                #[inline]
                pub fn contains<T>(&self) -> bool
                where
                    T: $trait_name,
                {
                    self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
                }

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

            #[derive(Serialize, Deserialize)]
            pub struct NamedSerdeAnyMap {
                map: HashMap<u64, HashMap<u64, Box<dyn $trait_name>>>,
            }

            impl NamedSerdeAnyMap {
                #[inline]
                pub fn get<T>(&self, name: &str) -> Option<&T>
                where
                    T: Any,
                {
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => h
                            .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_any().downcast_ref::<T>().unwrap()),
                    }
                }

                #[inline]
                pub fn by_typeid(&self, name: &str, typeid: &TypeId) -> Option<&dyn $trait_name> {
                    match self.map.get(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(AsRef::as_ref),
                    }
                }

                #[inline]
                pub fn get_mut<T>(&mut self, name: &str) -> Option<&mut T>
                where
                    T: Any,
                {
                    match self.map.get_mut(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => h
                            .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
                    }
                }

                #[inline]
                pub fn by_typeid_mut(
                    &mut self,
                    name: &str,
                    typeid: &TypeId,
                ) -> Option<&mut dyn $trait_name> {
                    match self.map.get_mut(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(AsMut::as_mut),
                    }
                }

                #[inline]
                pub fn get_all<T>(
                    &self,
                ) -> Option<
                    core::iter::Map<
                        Values<'_, u64, Box<dyn $trait_name>>,
                        fn(&Box<dyn $trait_name>) -> &T,
                    >,
                >
                where
                    T: Any,
                {
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => {
                            Some(h.values().map(|x| x.as_any().downcast_ref::<T>().unwrap()))
                        }
                    }
                }

                #[inline]
                pub fn all_by_typeid(
                    &self,
                    typeid: &TypeId,
                ) -> Option<
                    core::iter::Map<
                        Values<'_, u64, Box<dyn $trait_name>>,
                        fn(&Box<dyn $trait_name>) -> &dyn $trait_name,
                    >,
                > {
                    match self.map.get(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => Some(h.values().map(|x| x.as_ref())),
                    }
                }

                #[inline]
                pub fn get_all_mut<T>(
                    &mut self,
                ) -> Option<
                    core::iter::Map<
                        ValuesMut<'_, u64, Box<dyn $trait_name>>,
                        fn(&mut Box<dyn $trait_name>) -> &mut T,
                    >,
                >
                where
                    T: Any,
                {
                    match self.map.get_mut(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => Some(
                            h.values_mut()
                                .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
                        ),
                    }
                }

                #[inline]
                pub fn all_by_typeid_mut(
                    &mut self,
                    typeid: &TypeId,
                ) -> Option<
                    core::iter::Map<
                        ValuesMut<'_, u64, Box<dyn $trait_name>>,
                        fn(&mut Box<dyn $trait_name>) -> &mut dyn $trait_name,
                    >,
                > {
                    match self.map.get_mut(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => Some(h.values_mut().map(|x| x.as_mut())),
                    }
                }

                #[inline]
                pub fn all_typeids(
                    &self,
                ) -> core::iter::Map<
                    Keys<'_, u64, HashMap<u64, Box<dyn $trait_name>>>,
                    fn(&u64) -> TypeId,
                > {
                    self.map.keys().map(|x| pack_type_id(*x))
                }

                #[inline]
                pub fn for_each(
                    &self,
                    func: fn(&TypeId, &Box<dyn $trait_name>) -> Result<(), Error>,
                ) -> Result<(), Error> {
                    for (id, h) in self.map.iter() {
                        for x in h.values() {
                            func(&pack_type_id(*id), x)?;
                        }
                    }
                    Ok(())
                }

                #[inline]
                pub fn for_each_mut(
                    &mut self,
                    func: fn(&TypeId, &mut Box<dyn $trait_name>) -> Result<(), Error>,
                ) -> Result<(), Error> {
                    for (id, h) in self.map.iter_mut() {
                        for x in h.values_mut() {
                            func(&pack_type_id(*id), x)?;
                        }
                    }
                    Ok(())
                }

                #[inline]
                pub fn insert(&mut self, val: Box<dyn $trait_name>, name: &str) {
                    let id = unpack_type_id((*val).type_id());
                    if !self.map.contains_key(&id) {
                        self.map.insert(id, HashMap::default());
                    }
                    self.map
                        .get_mut(&id)
                        .unwrap()
                        .insert(xxhash_rust::xxh3::xxh3_64(name.as_bytes()), val);
                }

                #[inline]
                pub fn len(&self) -> usize {
                    self.map.len()
                }

                #[inline]
                pub fn contains_type<T>(&self) -> bool
                where
                    T: Any,
                {
                    self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
                }

                #[inline]
                pub fn contains<T>(&self, name: &str) -> bool
                where
                    T: Any,
                {
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => false,
                        Some(h) => h.contains_key(&xxhash_rust::xxh3::xxh3_64(name.as_bytes())),
                    }
                }

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

        impl<'a> Serialize for dyn $trait_name {
            fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                use serde::ser::SerializeSeq;

                let id = $crate::bolts::serdeany::unpack_type_id(self.type_id());
                let mut seq = se.serialize_seq(Some(2))?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&$crate::bolts::serdeany::Wrap(self))?;
                seq.end()
            }
        }

        impl<'de> Deserialize<'de> for Box<dyn $trait_name> {
            fn deserialize<D>(deserializer: D) -> Result<Box<dyn $trait_name>, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_seq($mod_name::BoxDynVisitor {})
            }
        }
    };
}

create_serde_registry_for_trait!(serdeany_registry, crate::bolts::serdeany::SerdeAny);
pub use serdeany_registry::*;

#[cfg(feature = "std")]
#[macro_export]
macro_rules! impl_serdeany {
    ($struct_name:ident) => {
        impl $crate::bolts::serdeany::SerdeAny for $struct_name {
            fn as_any(&self) -> &dyn core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
                self
            }
        }

        #[allow(non_snake_case)]
        #[$crate::ctor]
        fn $struct_name() {
            $crate::bolts::serdeany::RegistryBuilder::register::<$struct_name>();
        }
    };
}

#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! impl_serdeany {
    ($struct_name:ident) => {
        impl $crate::bolts::serdeany::SerdeAny for $struct_name {
            fn as_any(&self) -> &dyn core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
                self
            }
        }
    };
}
