use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::{Any, TypeId};
use core::slice::{Iter, IterMut};
use hashbrown::hash_map::{Keys, Values, ValuesMut};
use hashbrown::HashMap;

/// A map, storing any trait object by TypeId
#[derive(Default)]
pub struct MetaMap {
    map: HashMap<TypeId, Box<dyn Any>>,
}

impl MetaMap {
    #[inline]
    pub fn get<T>(&self) -> Option<&T>
    where
        T: Any,
    {
        self.map
            .get(&TypeId::of::<T>())
            .map(|x| x.as_ref().downcast_ref::<T>().unwrap())
    }

    #[inline]
    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Any,
    {
        self.map
            .get_mut(&TypeId::of::<T>())
            .map(|x| x.as_mut().downcast_mut::<T>().unwrap())
    }

    #[inline]
    pub fn insert<T>(&mut self, t: T)
    where
        T: Any,
    {
        self.map.insert(TypeId::of::<T>(), Box::new(t));
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn contains<T>(&self) -> bool
    where
        T: Any,
    {
        self.map.contains_key(&TypeId::of::<T>())
    }

    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

/// A map, allowing to store multiple elements of any given type, by TypeId.
pub struct MultiMetaMap {
    map: HashMap<TypeId, Vec<Box<dyn Any>>>,
}

impl MultiMetaMap {
    #[inline]
    pub fn get<T>(&self) -> Option<core::iter::Map<Iter<'_, Box<dyn Any>>, fn(&Box<dyn Any>) -> &T>>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(v) => Some(v.iter().map(|x| x.as_ref().downcast_ref::<T>().unwrap())),
        }
    }

    #[inline]
    pub fn get_mut<T>(
        &mut self,
    ) -> Option<core::iter::Map<IterMut<'_, Box<dyn Any>>, fn(&mut Box<dyn Any>) -> &mut T>>
    where
        T: Any,
    {
        match self.map.get_mut(&TypeId::of::<T>()) {
            None => None,
            Some(v) => Some(
                v.iter_mut()
                    .map(|x| x.as_mut().downcast_mut::<T>().unwrap()),
            ),
        }
    }

    #[inline]
    pub fn insert<T>(&mut self, t: T)
    where
        T: Any,
    {
        let typeid = TypeId::of::<T>();
        if !self.map.contains_key(&typeid) {
            self.map.insert(typeid, vec![Box::new(t)]);
        } else {
            self.map.get_mut(&typeid).unwrap().push(Box::new(t));
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn contains<T>(&self) -> bool
    where
        T: Any,
    {
        self.map.contains_key(&TypeId::of::<T>())
    }

    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

pub struct MetaInstanceMap {
    map: HashMap<TypeId, HashMap<*const (), Box<dyn Any>>>,
}

impl MetaInstanceMap {
    #[inline]
    pub fn get<T, U>(&self, instance: &U) -> Option<&T>
    where
        T: Any,
    {
        self.get_ptr::<T>(instance as *const _ as *const ())
    }

    pub fn get_ptr<T>(&self, instance: *const ()) -> Option<&T>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(h) => h
                .get(&instance)
                .map(|x| x.as_ref().downcast_ref::<T>().unwrap()),
        }
    }

    #[inline]
    pub fn get_mut<T, U>(&mut self, instance: &U) -> Option<&mut T>
    where
        T: Any,
    {
        self.get_mut_ptr::<T>(instance as *const _ as *const ())
    }

    pub fn get_mut_ptr<T>(&mut self, instance: *const ()) -> Option<&mut T>
    where
        T: Any,
    {
        match self.map.get_mut(&TypeId::of::<T>()) {
            None => None,
            Some(h) => h
                .get_mut(&instance)
                .map(|x| x.as_mut().downcast_mut::<T>().unwrap()),
        }
    }

    pub fn get_all<T>(
        &self,
    ) -> Option<core::iter::Map<Values<'_, *const (), Box<dyn Any>>, fn(&Box<dyn Any>) -> &T>>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(h) => Some(h.values().map(|x| x.as_ref().downcast_ref::<T>().unwrap())),
        }
    }

    pub fn get_all_mut<T>(
        &mut self,
    ) -> Option<
        core::iter::Map<ValuesMut<'_, *const (), Box<dyn Any>>, fn(&mut Box<dyn Any>) -> &mut T>,
    >
    where
        T: Any,
    {
        match self.map.get_mut(&TypeId::of::<T>()) {
            None => None,
            Some(h) => Some(
                h.values_mut()
                    .map(|x| x.as_mut().downcast_mut::<T>().unwrap()),
            ),
        }
    }

    #[inline]
    pub fn insert<T, U>(&mut self, t: T, instance: &U)
    where
        T: Any,
    {
        self.insert_ptr(t, instance as *const _ as *const ())
    }

    pub fn insert_ptr<T>(&mut self, t: T, instance: *const ())
    where
        T: Any,
    {
        let typeid = TypeId::of::<T>();
        if !self.map.contains_key(&typeid) {
            self.map.insert(typeid, HashMap::default());
        }
        self.map
            .get_mut(&typeid)
            .unwrap()
            .insert(instance, Box::new(t));
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
        self.map.contains_key(&TypeId::of::<T>())
    }

    #[inline]
    pub fn contains<T, U>(&self, instance: &U) -> bool
    where
        T: Any,
    {
        self.contains_ptr::<T>(instance as *const _ as *const ())
    }

    pub fn contains_ptr<T>(&self, instance: *const ()) -> bool
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => false,
            Some(h) => h.contains_key(&instance),
        }
    }

    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A map, allowing to store and get any object by type and name
pub struct NamedAnyMap<B>
where
    B: ?Sized + Any + AsAny,
{
    map: HashMap<TypeId, HashMap<&'static str, Box<B>>>,
}

impl<B> NamedAnyMap<B>
where
    B: ?Sized + Any + AsAny,
{
    pub fn get<T>(&self, name: &'static str) -> Option<&T>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(h) => h
                .get(&name)
                .map(|x| x.as_any().downcast_ref::<T>().unwrap()),
        }
    }

    pub fn by_typeid(&self, name: &'static str, typeid: &TypeId) -> Option<&B> {
        match self.map.get(typeid) {
            None => None,
            Some(h) => h.get(&name).map(|x| x.as_ref()),
        }
    }

    pub fn get_mut<T>(&mut self, name: &'static str) -> Option<&mut T>
    where
        T: Any,
    {
        match self.map.get_mut(&TypeId::of::<T>()) {
            None => None,
            Some(h) => h
                .get_mut(&name)
                .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
        }
    }

    pub fn by_typeid_mut(&mut self, name: &'static str, typeid: &TypeId) -> Option<&mut B> {
        match self.map.get_mut(typeid) {
            None => None,
            Some(h) => h.get_mut(&name).map(|x| x.as_mut()),
        }
    }

    pub fn get_all<T>(
        &self,
    ) -> Option<core::iter::Map<Values<'_, &'static str, Box<B>>, fn(&Box<B>) -> &T>>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(h) => Some(h.values().map(|x| x.as_any().downcast_ref::<T>().unwrap())),
        }
    }

    pub fn all_by_typeid(
        &self,
        typeid: &TypeId,
    ) -> Option<core::iter::Map<Values<'_, &'static str, Box<B>>, fn(&Box<B>) -> &B>> {
        match self.map.get(typeid) {
            None => None,
            Some(h) => Some(h.values().map(|x| x.as_ref())),
        }
    }

    pub fn get_all_mut<T>(
        &mut self,
    ) -> Option<core::iter::Map<ValuesMut<'_, &'static str, Box<B>>, fn(&mut Box<B>) -> &mut T>>
    where
        T: Any,
    {
        match self.map.get_mut(&TypeId::of::<T>()) {
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
    ) -> Option<core::iter::Map<ValuesMut<'_, &'static str, Box<B>>, fn(&mut Box<B>) -> &mut B>>
    {
        match self.map.get_mut(typeid) {
            None => None,
            Some(h) => Some(h.values_mut().map(|x| x.as_mut())),
        }
    }

    #[inline]
    pub fn all_typeids(&self) -> Keys<'_, TypeId, HashMap<&'static str, Box<B>>> {
        self.map.keys()
    }

    pub fn insert(&mut self, val: Box<B>, name: &'static str) {
        let typeid = val.type_id();
        if !self.map.contains_key(&typeid) {
            self.map.insert(typeid, HashMap::default());
        }
        self.map.get_mut(&typeid).unwrap().insert(name, val);
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
        self.map.contains_key(&TypeId::of::<T>())
    }

    #[inline]
    pub fn contains<T>(&self, name: &'static str) -> bool
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => false,
            Some(h) => h.contains_key(&name),
        }
    }

    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}
