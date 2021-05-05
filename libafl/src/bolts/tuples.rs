//! Compiletime lists used throughout the libafl universe

pub use tuple_list::{tuple_list, tuple_list_type, TupleList};

use core::any::TypeId;

use xxhash_rust::const_xxh3::xxh3_64;

#[cfg(feature = "RUSTC_IS_NIGHTLY")]
/// From https://stackoverflow.com/a/60138532/7658998
const fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    // Helper trait. `VALUE` is false, except for the specialization of the
    // case where `T == U`.
    trait TypeEq<U: ?Sized> {
        const VALUE: bool;
    }

    // Default implementation.
    impl<T: ?Sized, U: ?Sized> TypeEq<U> for T {
        default const VALUE: bool = false;
    }

    // Specialization for `T == U`.
    impl<T: ?Sized> TypeEq<T> for T {
        const VALUE: bool = true;
    }

    <T as TypeEq<U>>::VALUE
}

#[cfg(not(feature = "RUSTC_IS_NIGHTLY"))]
const fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    // BEWARE! This is not unsafe, it is SUPER UNSAFE
    true
}

pub trait HasLen {
    const LEN: usize;

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl HasLen for () {
    const LEN: usize = 0;

    fn len(&self) -> usize {
        0
    }
}

impl<Head, Tail> HasLen for (Head, Tail)
where
    Tail: HasLen,
{
    const LEN: usize = 1 + Tail::LEN;

    fn len(&self) -> usize {
        1 + self.1.len()
    }
}

pub trait HasNameId {
    fn const_name(&self) -> &'static str;

    fn name_id(&self) -> u64 {
        xxh3_64(self.const_name().as_bytes())
    }
}

pub trait HasNameIdTuple: HasLen {
    fn get_const_name(&self, index: usize) -> Option<&'static str>;

    fn get_name_id(&self, index: usize) -> Option<u64>;
}

impl HasNameIdTuple for () {
    fn get_const_name(&self, _index: usize) -> Option<&'static str> {
        None
    }

    fn get_name_id(&self, _index: usize) -> Option<u64> {
        None
    }
}

impl<Head, Tail> HasNameIdTuple for (Head, Tail)
where
    Head: HasNameId,
    Tail: HasNameIdTuple,
{
    fn get_const_name(&self, index: usize) -> Option<&'static str> {
        if index == 0 {
            Some(self.0.const_name())
        } else {
            self.1.get_const_name(index - 1)
        }
    }

    fn get_name_id(&self, index: usize) -> Option<u64> {
        if index == 0 {
            Some(self.0.name_id())
        } else {
            self.1.get_name_id(index - 1)
        }
    }
}

pub trait MatchFirstType {
    fn match_first_type<T: 'static>(&self) -> Option<&T>;
    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T>;
}

impl MatchFirstType for () {
    fn match_first_type<T: 'static>(&self) -> Option<&T> {
        None
    }
    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchFirstType for (Head, Tail)
where
    Head: 'static,
    Tail: MatchFirstType,
{
    fn match_first_type<T: 'static>(&self) -> Option<&T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            unsafe { (&self.0 as *const _ as *const T).as_ref() }
        } else {
            self.1.match_first_type::<T>()
        }
    }

    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }
        } else {
            self.1.match_first_type_mut::<T>()
        }
    }
}

pub trait MatchType {
    fn match_type<T: 'static>(&self, f: fn(t: &T));
    fn match_type_mut<T: 'static>(&mut self, f: fn(t: &mut T));
}

impl MatchType for () {
    fn match_type<T: 'static>(&self, _f: fn(t: &T)) {}
    fn match_type_mut<T: 'static>(&mut self, _f: fn(t: &mut T)) {}
}

impl<Head, Tail> MatchType for (Head, Tail)
where
    Head: 'static,
    Tail: MatchType,
{
    fn match_type<T: 'static>(&self, f: fn(t: &T)) {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (&self.0 as *const _ as *const T).as_ref() }.unwrap());
        }
        self.1.match_type::<T>(f);
    }

    fn match_type_mut<T: 'static>(&mut self, f: fn(t: &mut T)) {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }.unwrap());
        }
        self.1.match_type_mut::<T>(f);
    }
}

/// We need fixed names for many parts of this lib.
pub trait Named {
    /// Provide the name of this element.
    fn name(&self) -> &str;
}

pub trait NamedTuple: HasLen {
    fn get_name(&self, index: usize) -> Option<&str>;
}

impl NamedTuple for () {
    fn get_name(&self, _index: usize) -> Option<&str> {
        None
    }
}

impl<Head, Tail> NamedTuple for (Head, Tail)
where
    Head: Named,
    Tail: NamedTuple,
{
    fn get_name(&self, index: usize) -> Option<&str> {
        if index == 0 {
            Some(self.0.name())
        } else {
            self.1.get_name(index - 1)
        }
    }
}

/// This operation is unsafe with Rust stable, wait for https://stackoverflow.com/a/60138532/7658998
pub trait MatchName {
    fn match_name<T>(&self, name: &str) -> Option<&T>;
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T>;
}

impl MatchName for () {
    fn match_name<T>(&self, _name: &str) -> Option<&T> {
        None
    }
    fn match_name_mut<T>(&mut self, _name: &str) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchName for (Head, Tail)
where
    Head: Named,
    Tail: MatchName,
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if type_eq::<Head, T>() && name == self.0.name() {
            unsafe { (&self.0 as *const _ as *const T).as_ref() }
        } else {
            self.1.match_name::<T>(name)
        }
    }

    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if type_eq::<Head, T>() && name == self.0.name() {
            unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }
        } else {
            self.1.match_name_mut::<T>(name)
        }
    }
}

pub trait MatchNameAndType {
    fn match_name_type<T: 'static>(&self, name: &str) -> Option<&T>;
    fn match_name_type_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T>;
}

impl MatchNameAndType for () {
    fn match_name_type<T: 'static>(&self, _name: &str) -> Option<&T> {
        None
    }
    fn match_name_type_mut<T: 'static>(&mut self, _name: &str) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchNameAndType for (Head, Tail)
where
    Head: 'static + Named,
    Tail: MatchNameAndType,
{
    fn match_name_type<T: 'static>(&self, name: &str) -> Option<&T> {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() && name == self.0.name() {
            unsafe { (&self.0 as *const _ as *const T).as_ref() }
        } else {
            self.1.match_name_type::<T>(name)
        }
    }

    fn match_name_type_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T> {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() && name == self.0.name() {
            unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }
        } else {
            self.1.match_name_type_mut::<T>(name)
        }
    }
}

pub trait Prepend<T>: TupleList {
    type PreprendResult: TupleList;

    fn prepend(self, value: T) -> (T, Self::PreprendResult);
}

/// Implement prepend for tuple list.
impl<Tail, T> Prepend<T> for Tail
where
    Tail: TupleList,
{
    type PreprendResult = Self;

    fn prepend(self, value: T) -> (T, Self::PreprendResult) {
        (value, self)
    }
}

pub trait Append<T>: TupleList {
    type AppendResult: TupleList;

    fn append(self, value: T) -> Self::AppendResult;
}

/// Implement append for an empty tuple list.
impl<T> Append<T> for () {
    type AppendResult = (T, ());

    fn append(self, value: T) -> Self::AppendResult {
        (value, ())
    }
}

/// Implement append for non-empty tuple list.
impl<Head, Tail, T> Append<T> for (Head, Tail)
where
    Self: TupleList,
    Tail: Append<T>,
    (Head, Tail::AppendResult): TupleList,
{
    type AppendResult = (Head, Tail::AppendResult);

    fn append(self, value: T) -> Self::AppendResult {
        let (head, tail) = self;
        (head, tail.append(value))
    }
}

#[macro_export]
macro_rules! tuple_for_each {
    ($fn_name:ident, $trait_name:path, $tuple_name:ident, $body:expr) => {
        mod $fn_name {
            pub trait ForEach {
                fn for_each(&self);
            }

            impl ForEach for () {
                fn for_each(&self) {}
            }

            impl<Head, Tail> ForEach for (Head, Tail)
            where
                Head: $trait_name,
                Tail: tuple_list::TupleList + ForEach,
            {
                fn for_each(&self) {
                    ($body)(&self.0);
                    self.1.for_each();
                }
            }
        }
        {
            use $fn_name::*;

            $tuple_name.for_each();
        };
    };
}

#[macro_export]
macro_rules! tuple_for_each_mut {
    ($fn_name:ident, $trait_name:path, $tuple_name:ident, $body:expr) => {
        mod $fn_name {
            pub trait ForEachMut {
                fn for_each_mut(&mut self);
            }

            impl ForEachMut for () {
                fn for_each_mut(&mut self) {}
            }

            impl<Head, Tail> ForEachMut for (Head, Tail)
            where
                Head: $trait_name,
                Tail: tuple_list::TupleList + ForEachMut,
            {
                fn for_each_mut(&mut self) {
                    ($body)(&mut self.0);
                    self.1.for_each_mut();
                }
            }
        }
        {
            use $fn_name::*;

            $tuple_name.for_each_mut();
        };
    };
}

/*
pub fn test_macros() {

  let mut t = tuple_list!(1, "a");

  tuple_for_each!(f1, std::fmt::Display, t, |x| {
      println!("{}", x);
  });

  tuple_for_each_mut!(f2, std::fmt::Display, t, |x| {
      println!("{}", x);
  });

}
*/

/*

// Define trait and implement it for several primitive types.
trait PlusOne {
    fn plus_one(&mut self);
}
impl PlusOne for i32    { fn plus_one(&mut self) { *self += 1; } }
impl PlusOne for String { fn plus_one(&mut self) { self.push('1'); } }

// Now we have to implement trait for an empty tuple,
// thus defining initial condition.
impl PlusOne for () {
    fn plus_one(&mut self) {}
}

// Now we can implement trait for a non-empty tuple list,
// thus defining recursion and supporting tuple lists of arbitrary length.
impl<Head, Tail> PlusOne for (Head, Tail) where
    Head: PlusOne,
    Tail: PlusOne + TupleList,
{
    fn plus_one(&mut self) {
        self.0.plus_one();
        self.1.plus_one();
    }
}

*/
