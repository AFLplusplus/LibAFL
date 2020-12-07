use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::{Any, TypeId};
use core::slice::{Iter, IterMut};
use hashbrown::hash_map::{Values, ValuesMut};
use hashbrown::HashMap;

pub struct MetaMap {
    map: HashMap<TypeId, Box<dyn Any>>,
}

impl MetaMap {
    pub fn get<T>(&self) -> Option<&T>
    where
        T: Any,
    {
        self.map
            .get(&TypeId::of::<T>())
            .map(|x| x.as_ref().downcast_ref::<T>().unwrap())
    }

    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Any,
    {
        self.map
            .get_mut(&TypeId::of::<T>())
            .map(|x| x.as_mut().downcast_mut::<T>().unwrap())
    }

    pub fn insert<T>(&mut self, t: T)
    where
        T: Any,
    {
        self.map.insert(TypeId::of::<T>(), Box::new(t));
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

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

pub struct MultiMetaMap {
    map: HashMap<TypeId, Vec<Box<dyn Any>>>,
}

impl MultiMetaMap {
    pub fn get<T>(&self) -> Option<core::iter::Map<Iter<'_, Box<dyn Any>>, fn(&Box<dyn Any>) -> &T>>
    where
        T: Any,
    {
        match self.map.get(&TypeId::of::<T>()) {
            None => None,
            Some(v) => Some(v.iter().map(|x| x.as_ref().downcast_ref::<T>().unwrap())),
        }
    }

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

    pub fn len(&self) -> usize {
        self.map.len()
    }

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

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn contains_type<T>(&self) -> bool
    where
        T: Any,
    {
        self.map.contains_key(&TypeId::of::<T>())
    }

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
