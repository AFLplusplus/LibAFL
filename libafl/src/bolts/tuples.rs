//! Compiletime lists/tuples used throughout the `LibAFL` universe

pub use tuple_list::{tuple_list, tuple_list_type, TupleList};

use core::{
    any::TypeId,
    ptr::{addr_of, addr_of_mut},
};

use xxhash_rust::xxh3::xxh3_64;

#[rustversion::nightly]
/// From <https://stackoverflow.com/a/60138532/7658998>
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

#[rustversion::not(nightly)]
const fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    // BEWARE! This is not unsafe, it is SUPER UNSAFE
    true
}

/// Gets the length of the element
pub trait HasConstLen {
    /// The length as constant `usize`
    const LEN: usize;

    /// The length
    fn len(&self) -> usize;
    /// Returns true, if empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl HasConstLen for () {
    const LEN: usize = 0;

    fn len(&self) -> usize {
        0
    }
}

impl<Head, Tail> HasConstLen for (Head, Tail)
where
    Tail: HasConstLen,
{
    const LEN: usize = 1 + Tail::LEN;

    fn len(&self) -> usize {
        1 + self.1.len()
    }
}

/// Finds the `const_name` and `name_id`
pub trait HasNameId {
    /// Gets the `const_name` for this entry
    fn const_name(&self) -> &'static str;

    /// Gets the `name_id` for this entry
    fn name_id(&self) -> u64 {
        xxh3_64(self.const_name().as_bytes())
    }
}

/// Gets the id and `const_name` for the given index in a tuple
pub trait HasNameIdTuple: HasConstLen {
    /// Gets the `const_name` for the entry at the given index
    fn const_name_for(&self, index: usize) -> Option<&'static str>;

    /// Gets the `name_id` for the entry at the given index
    fn name_id_for(&self, index: usize) -> Option<u64>;
}

impl HasNameIdTuple for () {
    fn const_name_for(&self, _index: usize) -> Option<&'static str> {
        None
    }

    fn name_id_for(&self, _index: usize) -> Option<u64> {
        None
    }
}

impl<Head, Tail> HasNameIdTuple for (Head, Tail)
where
    Head: HasNameId,
    Tail: HasNameIdTuple,
{
    fn const_name_for(&self, index: usize) -> Option<&'static str> {
        if index == 0 {
            Some(self.0.const_name())
        } else {
            self.1.const_name_for(index - 1)
        }
    }

    fn name_id_for(&self, index: usize) -> Option<u64> {
        if index == 0 {
            Some(self.0.name_id())
        } else {
            self.1.name_id_for(index - 1)
        }
    }
}

/// Returns the first element with the given type
pub trait MatchFirstType {
    /// Returns the first element with the given type as borrow, or [`Option::None`]
    fn match_first_type<T: 'static>(&self) -> Option<&T>;
    /// Returns the first element with the given type as mutable borrow, or [`Option::None`]
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
            unsafe { (addr_of!(self.0) as *const T).as_ref() }
        } else {
            self.1.match_first_type::<T>()
        }
    }

    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            unsafe { (addr_of_mut!(self.0) as *mut T).as_mut() }
        } else {
            self.1.match_first_type_mut::<T>()
        }
    }
}

/// Match by type
pub trait MatchType {
    /// Match by type and call the passed `f` function with a borrow, if found
    fn match_type<T: 'static, FN: FnMut(&T)>(&self, f: &mut FN);
    /// Match by type and call the passed `f` function with a mutable borrow, if found
    fn match_type_mut<T: 'static, FN: FnMut(&mut T)>(&mut self, f: &mut FN);
}

impl MatchType for () {
    /// Match by type and call the passed `f` function with a borrow, if found
    fn match_type<T: 'static, FN: FnMut(&T)>(&self, _: &mut FN) {}
    /// Match by type and call the passed `f` function with a mutable borrow, if found
    fn match_type_mut<T: 'static, FN: FnMut(&mut T)>(&mut self, _: &mut FN) {}
}

impl<Head, Tail> MatchType for (Head, Tail)
where
    Head: 'static,
    Tail: MatchType,
{
    fn match_type<T: 'static, FN: FnMut(&T)>(&self, f: &mut FN) {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (addr_of!(self.0) as *const T).as_ref() }.unwrap());
        }
        self.1.match_type::<T, FN>(f);
    }

    fn match_type_mut<T: 'static, FN: FnMut(&mut T)>(&mut self, f: &mut FN) {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (addr_of_mut!(self.0) as *mut T).as_mut() }.unwrap());
        }
        self.1.match_type_mut::<T, FN>(f);
    }
}

/// We need fixed names for many parts of this lib.
pub trait Named {
    /// Provide the name of this element.
    fn name(&self) -> &str;
}

/// A named tuple
pub trait NamedTuple: HasConstLen {
    /// Gets the name of this tuple
    fn name(&self, index: usize) -> Option<&str>;
}

impl NamedTuple for () {
    fn name(&self, _index: usize) -> Option<&str> {
        None
    }
}

impl<Head, Tail> NamedTuple for (Head, Tail)
where
    Head: Named,
    Tail: NamedTuple,
{
    fn name(&self, index: usize) -> Option<&str> {
        if index == 0 {
            Some(self.0.name())
        } else {
            self.1.name(index - 1)
        }
    }
}

/// Match for a name and return the value
///
/// # Safety
/// This operation is unsafe with Rust stable, wait for [specialization](https://stackoverflow.com/a/60138532/7658998).
pub trait MatchName {
    /// Match for a name and return the borrowed value
    fn match_name<T>(&self, name: &str) -> Option<&T>;
    /// Match for a name and return the mut borrowed value
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
            unsafe { (addr_of!(self.0) as *const T).as_ref() }
        } else {
            self.1.match_name::<T>(name)
        }
    }

    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if type_eq::<Head, T>() && name == self.0.name() {
            unsafe { (addr_of_mut!(self.0) as *mut T).as_mut() }
        } else {
            self.1.match_name_mut::<T>(name)
        }
    }
}

/// Finds an element of a `type` by the given `name`.
pub trait MatchNameAndType {
    /// Finds an element of a `type` by the given `name`, and returns a borrow, or [`Option::None`].
    fn match_name_type<T: 'static>(&self, name: &str) -> Option<&T>;
    /// Finds an element of a `type` by the given `name`, and returns a mut borrow, or [`Option::None`].
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
            unsafe { (addr_of!(self.0) as *const T).as_ref() }
        } else {
            self.1.match_name_type::<T>(name)
        }
    }

    fn match_name_type_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T> {
        // Switch this check to https://stackoverflow.com/a/60138532/7658998 when in stable and remove 'static
        if TypeId::of::<T>() == TypeId::of::<Head>() && name == self.0.name() {
            unsafe { (addr_of_mut!(self.0) as *mut T).as_mut() }
        } else {
            self.1.match_name_type_mut::<T>(name)
        }
    }
}

/// Allows prepending of values to a tuple
pub trait Prepend<T> {
    /// The Resulting [`TupleList`], of an [`Prepend::prepend()`] call,
    /// including the prepended entry.
    type PreprendResult;

    /// Prepend a value to this tuple, returning a new tuple with prepended value.
    #[must_use]
    fn prepend(self, value: T) -> (T, Self::PreprendResult);
}

/// Implement prepend for tuple list.
impl<Tail, T> Prepend<T> for Tail {
    type PreprendResult = Self;

    fn prepend(self, value: T) -> (T, Self::PreprendResult) {
        (value, self)
    }
}

/// Append to a tuple
pub trait Append<T> {
    /// The Resulting [`TupleList`], of an [`Append::append()`] call,
    /// including the appended entry.
    type AppendResult;

    /// Append Value and return the tuple
    #[must_use]
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
    Tail: Append<T>,
{
    type AppendResult = (Head, Tail::AppendResult);

    fn append(self, value: T) -> Self::AppendResult {
        let (head, tail) = self;
        (head, tail.append(value))
    }
}

/// Merge two `TupleList`
pub trait Merge<T> {
    /// The Resulting [`TupleList`], of an [`Merge::merge()`] call
    type MergeResult;

    /// Merge and return the merged tuple
    #[must_use]
    fn merge(self, value: T) -> Self::MergeResult;
}

/// Implement merge for an empty tuple list.
impl<T> Merge<T> for () {
    type MergeResult = T;

    fn merge(self, value: T) -> Self::MergeResult {
        value
    }
}

/// Implement merge for non-empty tuple list.
impl<Head, Tail, T> Merge<T> for (Head, Tail)
where
    Tail: Merge<T>,
{
    type MergeResult = (Head, Tail::MergeResult);

    fn merge(self, value: T) -> Self::MergeResult {
        let (head, tail) = self;
        (head, tail.merge(value))
    }
}

/// Iterate over a tuple, executing the given `expr` for each element.
#[macro_export]
#[allow(clippy::items_after_statements)]
macro_rules! tuple_for_each {
    ($fn_name:ident, $trait_name:path, $tuple_name:ident, $body:expr) => {
        #[allow(clippy::items_after_statements)]
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
                #[allow(clippy::redundant_closure_call)]
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

/// Iterate over a tuple, executing the given `expr` for each element, granting mut access.
#[macro_export]
macro_rules! tuple_for_each_mut {
    ($fn_name:ident, $trait_name:path, $tuple_name:ident, $body:expr) => {
        #[allow(clippy::items_after_statements)]
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
                #[allow(clippy::redundant_closure_call)]
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

#[cfg(test)]
#[cfg(feature = "std")]
#[test]
#[allow(clippy::items_after_statements)]
pub fn test_macros() {
    let mut t = tuple_list!(1, "a");

    tuple_for_each!(f1, std::fmt::Display, t, |x| {
        println!("{}", x);
    });

    tuple_for_each_mut!(f2, std::fmt::Display, t, |x| {
        println!("{}", x);
    });
}

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
