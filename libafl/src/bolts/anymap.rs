//! Poor-rust-man's downcasts to have `AnyMap`

use alloc::boxed::Box;
use core::{
    any::{Any, TypeId},
    ptr::addr_of,
};

/// Convert to an Any trait object
pub trait AsAny: Any {
    /// Returns this as Any trait
    fn as_any(&self) -> &dyn Any;
    /// Returns this as mutable Any trait
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Returns this as boxed Any trait
    fn as_any_boxed(self: Box<Self>) -> Box<dyn Any>;
}

/// Implement `AsAny` for a type
#[macro_export]
macro_rules! impl_asany {
    ($struct_name:ident $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?) => {
        impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::bolts::anymap::AsAny for $struct_name $(< $( $lt ),+ >)? {
            fn as_any(&self) -> &dyn ::core::any::Any {
                self
            }

            fn as_any_mut(&mut self) -> &mut dyn ::core::any::Any {
                self
            }

            fn as_any_boxed(
                self: ::alloc::boxed::Box<Self>,
            ) -> ::alloc::boxed::Box<dyn ::core::any::Any> {
                self
            }
        }
    };
}

/// Get a `type_id` from its previously unpacked `u64`.
/// Opposite of [`unpack_type_id(id)`].
///
/// # Safety
/// Probably not safe for future compilers, fine for now.
#[must_use]
pub fn pack_type_id(id: u64) -> TypeId {
    assert_eq_size!(TypeId, u64);
    unsafe { *(addr_of!(id) as *const TypeId) }
}

/// Unpack a `type_id` to an `u64`
/// Opposite of [`pack_type_id(id)`].
///
/// # Safety
/// Probably not safe for future compilers, fine for now.
#[must_use]
pub fn unpack_type_id(id: TypeId) -> u64 {
    assert_eq_size!(TypeId, u64);
    unsafe { *(addr_of!(id) as *const u64) }
}

/// Create `AnyMap` and `NamedAnyMap` for a given trait
#[macro_export]
macro_rules! create_anymap_for_trait {
    ( $mod_name:ident, $parent_mod:path, $trait_name:ident $(< $( $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)? $(, $attrs:meta)*) => {
        mod $mod_name {
            use alloc::boxed::Box;
            use core::any::TypeId;

            use hashbrown::hash_map::{Keys, Values, ValuesMut};
            use hashbrown::HashMap;

            use $crate::bolts::anymap::{pack_type_id, unpack_type_id};
            use $crate::Error;

            use super::*;
            #[allow(unused_import_braces)]
            use $parent_mod::{$trait_name};

            /// An anymap containing trait objects
            #[derive(Default)]
            $(#[$attrs])*
            pub struct AnyMap $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? {
                map: HashMap<u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>,
            }

            #[allow(unused_qualifications)]
            impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? AnyMap $(< $( $lt ),+ >)? {
                /// Get an element from the map.
                #[must_use]
                #[inline]
                pub fn get<T>(&self) -> Option<&T>
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map
                        .get(&unpack_type_id(TypeId::of::<T>()))
                        .map(|x| x.as_ref().as_any().downcast_ref::<T>().unwrap())
                }

                /// Get a mutable borrow for an element in the map.
                #[must_use]
                #[inline]
                pub fn get_mut<T>(&mut self) -> Option<&mut T>
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map
                        .get_mut(&unpack_type_id(TypeId::of::<T>()))
                        .map(|x| x.as_mut().as_any_mut().downcast_mut::<T>().unwrap())
                }

                /// Remove an element in the map. Returns the removed element.
                #[must_use]
                #[inline]
                pub fn remove<T>(&mut self) -> Option<Box<T>>
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map
                        .remove(&unpack_type_id(TypeId::of::<T>()))
                        .map(|x| x.as_any_boxed().downcast::<T>().unwrap())
                }

                /// Insert an element into the map.
                #[inline]
                pub fn insert<T>(&mut self, t: T)
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map
                        .insert(unpack_type_id(TypeId::of::<T>()), Box::new(t));
                }

                /// Insert a boxed element into the map.
                #[inline]
                pub fn insert_boxed<T>(&mut self, t: Box<T>)
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map.insert(unpack_type_id(TypeId::of::<T>()), t);
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
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
                }

                /// Create a new [`AnyMap`].
                #[must_use]
                pub fn new() -> Self {
                    AnyMap {
                        map: HashMap::default(),
                    }
                }
            }

            /// An anymap, addressable by name and type, containing trait objects
            #[allow(unused_qualifications)]
            #[derive(Default)]
            $(#[$attrs])*
            pub struct NamedAnyMap $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? {
                map: HashMap<u64, HashMap<u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>>,
            }

            #[allow(unused_qualifications)]
            impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? NamedAnyMap $(< $( $lt ),+ >)? {
                /// Get an element by name
                #[must_use]
                #[inline]
                pub fn get<T>(&self, name: &str) -> Option<&T>
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => h
                            .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_any().downcast_ref::<T>().unwrap()),
                    }
                }

                /// Get an element of a given type contained in this map by [`TypeId`].
                #[must_use]
                #[allow(unused_qualifications)]
                #[inline]
                pub fn by_typeid(&self, name: &str, typeid: &TypeId) -> Option<&dyn $trait_name $(< $( $lt ),+ >)?> {
                    match self.map.get(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(AsRef::as_ref),
                    }
                }

                /// Get an element of a given type contained in this map by [`TypeId`], as mut.
                #[must_use]
                #[inline]
                pub fn get_mut<T>(&mut self, name: &str) -> Option<&mut T>
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    match self.map.get_mut(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => h
                            .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
                    }
                }

                /// Get an element of a given type contained in this map by [`TypeId`], as mut.
                #[must_use]
                #[inline]
                pub fn by_typeid_mut(
                    &mut self,
                    name: &str,
                    typeid: &TypeId,
                ) -> Option<&mut dyn $trait_name $(< $( $lt ),+ >)?> {
                    match self.map.get_mut(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => h
                            .get_mut(&xxhash_rust::xxh3::xxh3_64(name.as_bytes()))
                            .map(AsMut::as_mut),
                    }
                }

                /// Get all elements of a type contained in this map.
                #[must_use]
                #[allow(unused_qualifications)]
                #[inline]
                pub fn get_all<T>(
                    &self,
                ) -> Option<
                    core::iter::Map<
                        Values<'_, u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>,
                        fn(&Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> &T,
                    >,
                >
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    #[allow(clippy::manual_map)]
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => {
                            Some(h.values().map(|x| x.as_any().downcast_ref::<T>().unwrap()))
                        }
                    }
                }

                /// Get all elements of a given type contained in this map by [`TypeId`].
                #[must_use]
                #[allow(unused_qualifications)]
                #[inline]
                pub fn all_by_typeid(
                    &self,
                    typeid: &TypeId,
                ) -> Option<
                    core::iter::Map<
                        Values<'_, u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>,
                        fn(&Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> &dyn $trait_name $(< $( $lt ),+ >)?,
                    >,
                > {
                    #[allow(clippy::manual_map)]
                    match self.map.get(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => Some(h.values().map(|x| x.as_ref())),
                    }
                }

                /// Get all elements contained in this map, as mut.
                #[inline]
                #[allow(unused_qualifications)]
                pub fn get_all_mut<T>(
                    &mut self,
                ) -> Option<
                    core::iter::Map<
                        ValuesMut<'_, u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>,
                        fn(&mut Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> &mut T,
                    >,
                >
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    #[allow(clippy::manual_map)]
                    match self.map.get_mut(&unpack_type_id(TypeId::of::<T>())) {
                        None => None,
                        Some(h) => Some(
                            h.values_mut()
                                .map(|x| x.as_any_mut().downcast_mut::<T>().unwrap()),
                        ),
                    }
                }

                /// Get all [`TypeId`]`s` contained in this map, as mut.
                #[inline]
                #[allow(unused_qualifications)]
                pub fn all_by_typeid_mut(
                    &mut self,
                    typeid: &TypeId,
                ) -> Option<
                    core::iter::Map<
                        ValuesMut<'_, u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>,
                        fn(&mut Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> &mut dyn $trait_name $(< $( $lt ),+ >)?,
                    >,
                > {
                    #[allow(clippy::manual_map)]
                    match self.map.get_mut(&unpack_type_id(*typeid)) {
                        None => None,
                        Some(h) => Some(h.values_mut().map(|x| x.as_mut())),
                    }
                }

                /// Get all [`TypeId`]`s` contained in this map.
                #[inline]
                #[allow(unused_qualifications)]
                pub fn all_typeids(
                    &self,
                ) -> core::iter::Map<
                    Keys<'_, u64, HashMap<u64, Box<dyn $trait_name $(< $( $lt ),+ >)?>>>,
                    fn(&u64) -> TypeId,
                > {
                    self.map.keys().map(|x| pack_type_id(*x))
                }

                /// Run `func` for each element in this map.
                #[inline]
                #[allow(unused_qualifications)]
                pub fn for_each<F: FnMut(&TypeId, &Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> Result<(), Error>>(
                    &self,
                    func: &mut F,
                ) -> Result<(), Error> {
                    for (id, h) in self.map.iter() {
                        for x in h.values() {
                            func(&pack_type_id(*id), x)?;
                        }
                    }
                    Ok(())
                }

                /// Run `func` for each element in this map, getting a mutable borrow.
                #[inline]
                pub fn for_each_mut<F: FnMut(&TypeId, &mut Box<dyn $trait_name $(< $( $lt ),+ >)?>) -> Result<(), Error>>(
                    &mut self,
                    func: &mut F,
                ) -> Result<(), Error> {
                    for (id, h) in self.map.iter_mut() {
                        for x in h.values_mut() {
                            func(&pack_type_id(*id), x)?;
                        }
                    }
                    Ok(())
                }

                /// Insert an element into this map.
                #[inline]
                #[allow(unused_qualifications)]
                pub fn insert(&mut self, val: Box<dyn $trait_name $(< $( $lt ),+ >)?>, name: &str) {
                    let id = unpack_type_id((*val).type_id());
                    if !self.map.contains_key(&id) {
                        self.map.insert(id, HashMap::default());
                    }
                    self.map
                        .get_mut(&id)
                        .unwrap()
                        .insert(xxhash_rust::xxh3::xxh3_64(name.as_bytes()), val);
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
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    self.map.contains_key(&unpack_type_id(TypeId::of::<T>()))
                }

                /// Returns if the element by a given `name` is contained in this map.
                #[must_use]
                #[inline]
                pub fn contains<T>(&self, name: &str) -> bool
                where
                    T: $trait_name $(< $( $lt ),+ >)?,
                {
                    match self.map.get(&unpack_type_id(TypeId::of::<T>())) {
                        None => false,
                        Some(h) => h.contains_key(&xxhash_rust::xxh3::xxh3_64(name.as_bytes())),
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
        }
    }
}
