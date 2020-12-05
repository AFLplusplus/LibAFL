use hashbrown::HashMap;
use serde::{Serialize, Deserialize};

use core::default::Default;
use core::any::{TypeId, Any};
use core::fmt;

pub fn pack_type_id(id: u64) -> TypeId {
    unsafe {
        *(&id as *const u64 as *const TypeId)
    }
}

pub fn unpack_type_id(id: TypeId) -> u64 {
    unsafe {
        *(&id as *const _ as *const u64)
    }
}

pub trait SerdeAny : Any + erased_serde::Serialize {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

type DeserializeCallback = fn(&mut dyn erased_serde::Deserializer) -> Result<Box<dyn SerdeAny>, erased_serde::Error>;

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
        where S: serde::Serializer
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

impl<'de> serde::de::DeserializeSeed<'de> for DeserializeCallbackSeed{
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
        let cb = unsafe { *REGISTRY.deserializers.as_ref().unwrap().get(&id).expect("Cannot deserialize an unregistered SerdeAny") };
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
    finalized: bool
}

impl Registry {
    pub fn register<T>(&mut self) where T: SerdeAny + Serialize + serde::de::DeserializeOwned {
        if self.finalized {
            panic!("Global Registry of SerdeAny types is already finalized!");
        }
    
        let deserializers = self.deserializers.get_or_insert_with(|| HashMap::default());
        deserializers.insert(unpack_type_id(TypeId::of::<T>()), |de| Ok(Box::new(erased_serde::deserialize::<T>(de)?)));
    }
    
    pub fn finalize(&mut self) {
        self.finalized = true;
    }
}

static mut REGISTRY: Registry = Registry { deserializers: None, finalized: false };

pub struct RegistryBuilder {}
impl RegistryBuilder {
    pub fn register<T>() where T: SerdeAny + Serialize + serde::de::DeserializeOwned {
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
    map: HashMap<u64, Box<dyn SerdeAny>>
}

impl SerdeAnyMap {
    pub fn get<T>(&self) -> Option<&T> where T: SerdeAny {
        self.map.get(&unpack_type_id(TypeId::of::<T>())).map(|x| x.as_ref().as_any().downcast_ref::<T>().unwrap())
    }
    
    pub fn get_mut<T>(&mut self) -> Option<&mut T> where T: SerdeAny {
        self.map.get_mut(&unpack_type_id(TypeId::of::<T>())).map(|x| x.as_mut().as_any_mut().downcast_mut::<T>().unwrap())
    }
    
    pub fn insert<T>(&mut self, t: T) where T: SerdeAny {
        self.map.insert(unpack_type_id(TypeId::of::<T>()), Box::new(t));
    }
    
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    pub fn contains<T>(&self) -> bool where T: SerdeAny {
        self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
    }
    
    pub fn new() -> Self {
        SerdeAnyMap { map: HashMap::default() }
    }
}
