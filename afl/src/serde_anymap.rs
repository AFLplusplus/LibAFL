use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use alloc::boxed::Box;
use core::any::{Any, TypeId};
use core::default::Default;
use core::fmt;
use core::slice::{Iter, IterMut};
use hashbrown::hash_map::{Keys, Values, ValuesMut};

use crate::AflError;

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

type DeserializeCallback =
    fn(&mut dyn erased_serde::Deserializer) -> Result<Box<dyn SerdeAny>, erased_serde::Error>;

struct Wrap<'a, T: ?Sized>(pub &'a T);
impl<'a, T> Serialize for Wrap<'a, T>
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

impl<'a> serde::Serialize for dyn SerdeAny + 'a {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let id = unpack_type_id(self.type_id());
        let mut seq = se.serialize_seq(Some(2))?;
        seq.serialize_element(&id)?;
        seq.serialize_element(&Wrap(self))?;
        seq.end()
    }
}

struct DeserializeCallbackSeed {
    pub cb: DeserializeCallback,
}

impl<'de> serde::de::DeserializeSeed<'de> for DeserializeCallbackSeed {
    type Value = Box<dyn SerdeAny>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let mut erased = erased_serde::Deserializer::erase(deserializer);
        (self.cb)(&mut erased).map_err(serde::de::Error::custom)
    }
}

struct BoxAnyVisitor {}
impl<'de> serde::de::Visitor<'de> for BoxAnyVisitor {
    type Value = Box<dyn SerdeAny>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Expecting a serialized SerdeAny trait object (Box<dyn SerdeAny>)")
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Box<dyn SerdeAny>, V::Error>
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
                .expect("Cannot deserialize an unregistered SerdeAny")
        };
        let seed = DeserializeCallbackSeed { cb: cb };
        let obj: Box<dyn SerdeAny> = visitor.next_element_seed(seed)?.unwrap();
        Ok(obj)
    }
}

impl<'de> Deserialize<'de> for Box<dyn SerdeAny> {
    fn deserialize<D>(deserializer: D) -> Result<Box<dyn SerdeAny>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoxAnyVisitor {})
    }
}

pub struct Registry {
    deserializers: Option<HashMap<u64, DeserializeCallback>>,
    finalized: bool,
}

impl Registry {
    pub fn register<T>(&mut self)
    where
        T: SerdeAny + Serialize + serde::de::DeserializeOwned,
    {
        if self.finalized {
            panic!("Global Registry of SerdeAny types is already finalized!");
        }

        let deserializers = self.deserializers.get_or_insert_with(|| HashMap::default());
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
        T: SerdeAny + Serialize + serde::de::DeserializeOwned,
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

#[derive(Default, Serialize, Deserialize)]
pub struct SerdeAnyMap {
    map: HashMap<u64, Box<dyn SerdeAny>>,
}

impl SerdeAnyMap {
    pub fn get<T>(&self) -> Option<&T>
    where
        T: SerdeAny,
    {
        self.map
            .get(&unpack_type_id(TypeId::of::<T>()))
            .map(|x| x.as_ref().as_any().downcast_ref::<T>().unwrap())
    }

    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: SerdeAny,
    {
        self.map
            .get_mut(&unpack_type_id(TypeId::of::<T>()))
            .map(|x| x.as_mut().as_any_mut().downcast_mut::<T>().unwrap())
    }

    pub fn insert<T>(&mut self, t: T)
    where
        T: SerdeAny,
    {
        self.map
            .insert(unpack_type_id(TypeId::of::<T>()), Box::new(t));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn contains<T>(&self) -> bool
    where
        T: SerdeAny,
    {
        self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
    }

    pub fn new() -> Self {
        SerdeAnyMap {
            map: HashMap::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct NamedSerdeAnyMap<B>
where
    B: ?Sized + SerdeAny,
{
    map: HashMap<u64, HashMap<u64, Box<B>>>,
}

impl<B> NamedSerdeAnyMap<B>
where
    B: ?Sized + SerdeAny,
{
    pub fn get<T>(&self, name: &'static str) -> Option<&T>
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

    pub fn by_typeid(&self, name: &'static str, typeid: &TypeId) -> Option<&B> {
        match self.map.get(&unpack_type_id(*typeid)) {
            None => None,
            Some(h) => h
                .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                .map(|x| x.as_ref()),
        }
    }

    pub fn get_mut<T>(&mut self, name: &'static str) -> Option<&mut T>
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

    pub fn by_typeid_mut(&mut self, name: &'static str, typeid: &TypeId) -> Option<&mut B> {
        match self.map.get_mut(&unpack_type_id(*typeid)) {
            None => None,
            Some(h) => h
                .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                .map(|x| x.as_mut()),
        }
    }

    pub fn get_all<T>(&self) -> Option<core::iter::Map<Values<'_, u64, Box<B>>, fn(&Box<B>) -> &T>>
    where
        T: Any,
    {
        match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
            None => None,
            Some(h) => Some(h.values().map(|x| x.as_any().downcast_ref::<T>().unwrap())),
        }
    }

    pub fn all_by_typeid(
        &self,
        typeid: &TypeId,
    ) -> Option<core::iter::Map<Values<'_, u64, Box<B>>, fn(&Box<B>) -> &B>> {
        match self.map.get(&unpack_type_id(*typeid)) {
            None => None,
            Some(h) => Some(h.values().map(|x| x.as_ref())),
        }
    }

    pub fn get_all_mut<T>(
        &mut self,
    ) -> Option<core::iter::Map<ValuesMut<'_, u64, Box<B>>, fn(&mut Box<B>) -> &mut T>>
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

    pub fn all_by_typeid_mut(
        &mut self,
        typeid: &TypeId,
    ) -> Option<core::iter::Map<ValuesMut<'_, u64, Box<B>>, fn(&mut Box<B>) -> &mut B>> {
        match self.map.get_mut(&unpack_type_id(*typeid)) {
            None => None,
            Some(h) => Some(h.values_mut().map(|x| x.as_mut())),
        }
    }

    pub fn all_typeids(
        &self,
    ) -> core::iter::Map<Keys<'_, u64, HashMap<u64, Box<B>>>, fn(&u64) -> TypeId> {
        self.map.keys().map(|x| pack_type_id(*x))
    }

    pub fn for_each(
        &self,
        func: fn(&TypeId, &Box<B>) -> Result<(), AflError>,
    ) -> Result<(), AflError> {
        for (id, h) in self.map.iter() {
            for x in h.values() {
                func(&pack_type_id(*id), x)?;
            }
        }
        Ok(())
    }

    pub fn for_each_mut(
        &mut self,
        func: fn(&TypeId, &mut Box<B>) -> Result<(), AflError>,
    ) -> Result<(), AflError> {
        for (id, h) in self.map.iter_mut() {
            for x in h.values_mut() {
                func(&pack_type_id(*id), x)?;
            }
        }
        Ok(())
    }

    pub fn insert(&mut self, val: Box<B>, name: &'static str) {
        let id = unpack_type_id(val.type_id());
        if !self.map.contains_key(&id) {
            self.map.insert(id, HashMap::default());
        }
        self.map
            .get_mut(&id)
            .unwrap()
            .insert(xxhash_rust::xxh3::xxh3_64(name.as_bytes()), val);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn contains_type<T>(&self) -> bool
    where
        T: Any,
    {
        self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
    }

    pub fn contains<T>(&self, name: &'static str) -> bool
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

impl<B> Default for NamedSerdeAnyMap<B>
where
    B: ?Sized + SerdeAny,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
pub enum Ptr<'a, T: 'a + ?Sized> {
    Ref(&'a T),
    Owned(Box<T>),
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

#[derive(Serialize)]
pub enum PtrMut<'a, T: 'a + ?Sized> {
    Ref(&'a mut T),
    Owned(Box<T>),
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

#[derive(Serialize)]
pub enum Slice<'a, T: 'a + Sized> {
    Ref(&'a [T]),
    Owned(Vec<T>),
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

#[derive(Serialize)]
pub enum SliceMut<'a, T: 'a + Sized> {
    Ref(&'a mut [T]),
    Owned(Vec<T>),
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
