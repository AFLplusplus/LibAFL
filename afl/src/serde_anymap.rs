use serde::Deserialize;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::{Any, TypeId};

pub fn pack_type_id(id: u64) -> TypeId {
    unsafe { *(&id as *const u64 as *const TypeId) }
}

pub fn unpack_type_id(id: TypeId) -> u64 {
    unsafe { *(&id as *const _ as *const u64) }
}

pub trait SerdeAny: Any + erased_serde::Serialize {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

pub struct Wrap<'a, T: ?Sized>(pub &'a T);
impl<'a, T> serde::Serialize for Wrap<'a, T>
where
    T: ?Sized + erased_serde::Serialize + 'a,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
            use alloc::string::String;
            use core::any::{Any, TypeId};
            use core::fmt;
            use serde::{Deserialize, Serialize};

            use hashbrown::hash_map::{Keys, Values, ValuesMut};
            use hashbrown::HashMap;

            use $crate::serde_anymap::{
                pack_type_id, unpack_type_id, DeserializeCallback, DeserializeCallbackSeed,
            };
            use $crate::AflError;

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
                    let seed = DeserializeCallbackSeed::<dyn $trait_name> { cb: cb };
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
                    T: $trait_name + serde::Serialize + serde::de::DeserializeOwned,
                {
                    if self.finalized {
                        panic!("Registry is already finalized!");
                    }

                    let deserializers =
                        self.deserializers.get_or_insert_with(|| HashMap::default());
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

            pub struct RegistryBuilder {}
            impl RegistryBuilder {
                pub fn register<T>()
                where
                    T: $trait_name + serde::Serialize + serde::de::DeserializeOwned,
                {
                    unsafe {
                        REGISTRY.register::<T>();
                    }
                }

                pub fn finalize() {
                    unsafe {
                        REGISTRY.finalize();
                    }
                }
            }

            #[derive(Serialize, Deserialize)]
            pub struct SerdeAnyMap {
                map: HashMap<u64, Box<dyn $trait_name>>,
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
                pub fn get<T>(&self, name: &String) -> Option<&T>
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
                pub fn by_typeid(
                    &self,
                    name: &String,
                    typeid: &TypeId,
                ) -> Option<&dyn $trait_name> {
                    match self.map.get(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_ref()),
                    }
                }

                #[inline]
                pub fn get_mut<T>(&mut self, name: &String) -> Option<&mut T>
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
                    name: &String,
                    typeid: &TypeId,
                ) -> Option<&mut dyn $trait_name> {
                    match self.map.get_mut(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_mut()),
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
                    func: fn(&TypeId, &Box<dyn $trait_name>) -> Result<(), AflError>,
                ) -> Result<(), AflError> {
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
                    func: fn(&TypeId, &mut Box<dyn $trait_name>) -> Result<(), AflError>,
                ) -> Result<(), AflError> {
                    for (id, h) in self.map.iter_mut() {
                        for x in h.values_mut() {
                            func(&pack_type_id(*id), x)?;
                        }
                    }
                    Ok(())
                }

                #[inline]
                pub fn insert(&mut self, val: Box<dyn $trait_name>, name: &String) {
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
                pub fn contains<T>(&self, name: &String) -> bool
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

        impl<'a> serde::Serialize for dyn $trait_name {
            fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                let id = $crate::serde_anymap::unpack_type_id(self.type_id());
                let mut seq = se.serialize_seq(Some(2))?;
                seq.serialize_element(&id)?;
                seq.serialize_element(&$crate::serde_anymap::Wrap(self))?;
                seq.end()
            }
        }

        impl<'de> serde::Deserialize<'de> for Box<dyn $trait_name> {
            fn deserialize<D>(deserializer: D) -> Result<Box<dyn $trait_name>, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_seq($mod_name::BoxDynVisitor {})
            }
        }
    };
}

create_serde_registry_for_trait!(serdeany_serde, crate::serde_anymap::SerdeAny);
pub use serdeany_serde::*;

pub enum Ptr<'a, T: 'a + ?Sized> {
    Ref(&'a T),
    Owned(Box<T>),
}

impl<'a, T: 'a + ?Sized + serde::Serialize> serde::Serialize for Ptr<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Ptr::Ref(r) => r.serialize(se),
            Ptr::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + ?Sized> Deserialize<'de> for Ptr<'a, T>
where
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(Ptr::Owned)
    }
}

impl<'a, T: Sized> Ptr<'a, T> {
    pub fn as_ref(&self) -> &T {
        match self {
            Ptr::Ref(r) => r,
            Ptr::Owned(v) => v.as_ref(),
        }
    }
}

pub enum PtrMut<'a, T: 'a + ?Sized> {
    Ref(&'a mut T),
    Owned(Box<T>),
}

impl<'a, T: 'a + ?Sized + serde::Serialize> serde::Serialize for PtrMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PtrMut::Ref(r) => r.serialize(se),
            PtrMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + ?Sized> Deserialize<'de> for PtrMut<'a, T>
where
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(PtrMut::Owned)
    }
}

impl<'a, T: Sized> PtrMut<'a, T> {
    pub fn as_ref(&self) -> &T {
        match self {
            PtrMut::Ref(r) => r,
            PtrMut::Owned(v) => v.as_ref(),
        }
    }

    pub fn as_mut(&mut self) -> &T {
        match self {
            PtrMut::Ref(r) => r,
            PtrMut::Owned(v) => v.as_mut(),
        }
    }
}

pub enum Slice<'a, T: 'a + Sized> {
    Ref(&'a [T]),
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + serde::Serialize> serde::Serialize for Slice<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Slice::Ref(r) => r.serialize(se),
            Slice::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for Slice<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(Slice::Owned)
    }
}

impl<'a, T: Sized> Slice<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Slice::Ref(r) => r,
            Slice::Owned(v) => v.as_slice(),
        }
    }
}

pub enum SliceMut<'a, T: 'a + Sized> {
    Ref(&'a mut [T]),
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + serde::Serialize> serde::Serialize for SliceMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SliceMut::Ref(r) => r.serialize(se),
            SliceMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for SliceMut<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(SliceMut::Owned)
    }
}

impl<'a, T: Sized> SliceMut<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &[T] {
        match self {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_mut_slice(),
        }
    }
}

pub enum Array<T: Sized + serde::Serialize> {
    Cptr((*const T, usize)),
    Owned(Vec<T>),
}

impl<T: Sized + serde::Serialize> serde::Serialize for Array<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + serde::Serialize> Deserialize<'de> for Array<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(Array::Owned)
    }
}

impl<T: Sized + serde::Serialize> Array<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Array::Cptr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            Array::Owned(v) => v.as_slice(),
        }
    }
}

pub enum ArrayMut<T: Sized + serde::Serialize> {
    Cptr((*mut T, usize)),
    Owned(Vec<T>),
}

impl<T: Sized + serde::Serialize> serde::Serialize for ArrayMut<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + serde::Serialize> Deserialize<'de> for ArrayMut<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(ArrayMut::Owned)
    }
}

impl<T: Sized + serde::Serialize> ArrayMut<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            ArrayMut::Cptr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            ArrayMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            ArrayMut::Cptr(p) => unsafe { core::slice::from_raw_parts_mut(p.0, p.1) },
            ArrayMut::Owned(v) => v.as_mut_slice(),
        }
    }
}
