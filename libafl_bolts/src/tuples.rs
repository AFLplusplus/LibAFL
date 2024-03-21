//! Compiletime lists/tuples used throughout the `LibAFL` universe

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[rustversion::not(nightly)]
use core::any::type_name;
use core::{
    any::TypeId,
    ptr::{addr_of, addr_of_mut},
};

pub use tuple_list::{tuple_list, tuple_list_type, TupleList};

#[cfg(any(feature = "xxh3", feature = "alloc"))]
use crate::hash_std;
use crate::{HasLen, Named};

/// Returns if the type `T` is equal to `U`
/// From <https://stackoverflow.com/a/60138532/7658998>
#[rustversion::nightly]
#[inline]
#[must_use]
pub const fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
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

/// Returns if the type `T` is equal to `U`
/// As this relies on [`type_name`](https://doc.rust-lang.org/std/any/fn.type_name.html#note) internally,
/// there is a chance for collisions.
/// Use `nightly` if you need a perfect match at all times.
#[rustversion::not(nightly)]
#[inline]
#[must_use]
pub fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    type_name::<T>() == type_name::<U>()
}

/// Borrow each member of the tuple
pub trait SplitBorrow<'a> {
    /// The Resulting [`TupleList`], of an [`SplitBorrow::borrow()`] call
    type SplitBorrowResult;
    /// The Resulting [`TupleList`], of an [`SplitBorrow::borrow_mut()`] call
    type SplitBorrowMutResult;

    /// Return a tuple of borrowed references
    fn borrow(&'a self) -> Self::SplitBorrowResult;
    /// Return a tuple of borrowed mutable references
    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult;
}

impl<'a> SplitBorrow<'a> for () {
    type SplitBorrowResult = ();
    type SplitBorrowMutResult = ();

    fn borrow(&'a self) -> Self::SplitBorrowResult {}

    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult {}
}

impl<'a, Head, Tail> SplitBorrow<'a> for (Head, Tail)
where
    Head: 'a,
    Tail: SplitBorrow<'a>,
{
    type SplitBorrowResult = (Option<&'a Head>, Tail::SplitBorrowResult);
    type SplitBorrowMutResult = (Option<&'a mut Head>, Tail::SplitBorrowMutResult);

    fn borrow(&'a self) -> Self::SplitBorrowResult {
        (Some(&self.0), self.1.borrow())
    }

    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult {
        (Some(&mut self.0), self.1.borrow_mut())
    }
}

/// Create a [`Vec`] from a tuple list or similar
/// (We need this trait since we cannot implement `Into` for foreign types)
#[cfg(feature = "alloc")]
pub trait IntoVec<T> {
    /// Convert this into a [`Vec`], reversed.
    /// (Having this method around makes some implementations more performant)
    fn into_vec_reversed(self) -> Vec<T>
    where
        Self: Sized,
    {
        let mut ret = self.into_vec();
        ret.reverse();
        ret
    }

    /// Convert this into a [`Vec`].
    fn into_vec(self) -> Vec<T>;
}

#[cfg(feature = "alloc")]
impl<T> IntoVec<T> for () {
    #[inline]
    fn into_vec(self) -> Vec<T> {
        Vec::new()
    }
}

/// Gets the length of the element
pub trait HasConstLen {
    /// The length as constant `usize`
    const LEN: usize;
}

impl HasConstLen for () {
    const LEN: usize = 0;
}

impl<Head, Tail> HasConstLen for (Head, Tail)
where
    Tail: HasConstLen,
{
    const LEN: usize = 1 + Tail::LEN;
}

impl<Head, Tail> HasLen for (Head, Tail)
where
    Tail: HasLen,
{
    #[inline]
    fn len(&self) -> usize {
        self.1.len() + 1
    }
}

impl<Tail> HasLen for (Tail,)
where
    Tail: HasLen,
{
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl HasLen for () {
    #[inline]
    fn len(&self) -> usize {
        0
    }
}

/// Finds the `const_name` and `name_id`
pub trait HasNameId {
    /// Gets the `const_name` for this entry
    fn const_name(&self) -> &'static str;

    /// Gets the `name_id` for this entry
    fn name_id(&self) -> u64 {
        hash_std(self.const_name().as_bytes())
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

/// Returns the first element with the given type (dereference mut version)
pub trait ExtractFirstRefType {
    /// Returns the first element with the given type as borrow, or [`Option::None`]
    fn take<'a, T: 'static>(self) -> (Option<&'a T>, Self);
}

impl ExtractFirstRefType for () {
    fn take<'a, T: 'static>(self) -> (Option<&'a T>, Self) {
        (None, ())
    }
}

impl<Head, Tail> ExtractFirstRefType for (Option<&Head>, Tail)
where
    Head: 'static,
    Tail: ExtractFirstRefType,
{
    fn take<'a, T: 'static>(mut self) -> (Option<&'a T>, Self) {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            let r = self.0.take();
            (unsafe { core::mem::transmute(r) }, self)
        } else {
            let (r, tail) = self.1.take::<T>();
            (r, (self.0, tail))
        }
    }
}

impl<Head, Tail> ExtractFirstRefType for (Option<&mut Head>, Tail)
where
    Head: 'static,
    Tail: ExtractFirstRefType,
{
    fn take<'a, T: 'static>(mut self) -> (Option<&'a T>, Self) {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            let r = self.0.take();
            (unsafe { core::mem::transmute(r) }, self)
        } else {
            let (r, tail) = self.1.take::<T>();
            (r, (self.0, tail))
        }
    }
}

/// Returns the first element with the given type (dereference mut version)
pub trait ExtractFirstRefMutType {
    /// Returns the first element with the given type as borrow, or [`Option::None`]
    fn take<'a, T: 'static>(self) -> (Option<&'a mut T>, Self);
}

impl ExtractFirstRefMutType for () {
    fn take<'a, T: 'static>(self) -> (Option<&'a mut T>, Self) {
        (None, ())
    }
}

impl<Head, Tail> ExtractFirstRefMutType for (Option<&mut Head>, Tail)
where
    Head: 'static,
    Tail: ExtractFirstRefMutType,
{
    fn take<'a, T: 'static>(mut self) -> (Option<&'a mut T>, Self) {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            let r = self.0.take();
            (unsafe { core::mem::transmute(r) }, self)
        } else {
            let (r, tail) = self.1.take::<T>();
            (r, (self.0, tail))
        }
    }
}

/// Borrow each member of the tuple
pub trait SplitBorrowExtractFirstType<'a> {
    /// The Resulting [`TupleList`], of an [`SplitBorrow::borrow()`] call
    type SplitBorrowResult: ExtractFirstRefType;
    /// The Resulting [`TupleList`], of an [`SplitBorrow::borrow_mut()`] call
    type SplitBorrowMutResult: ExtractFirstRefType + ExtractFirstRefMutType;

    /// Return a tuple of borrowed references
    fn borrow(&'a self) -> Self::SplitBorrowResult;
    /// Return a tuple of borrowed mutable references
    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult;
}

impl<'a> SplitBorrowExtractFirstType<'a> for () {
    type SplitBorrowResult = ();
    type SplitBorrowMutResult = ();

    fn borrow(&'a self) -> Self::SplitBorrowResult {}

    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult {}
}

impl<'a, Head, Tail> SplitBorrowExtractFirstType<'a> for (Head, Tail)
where
    Head: 'static,
    Tail: SplitBorrowExtractFirstType<'a>,
{
    type SplitBorrowResult = (Option<&'a Head>, Tail::SplitBorrowResult);
    type SplitBorrowMutResult = (Option<&'a mut Head>, Tail::SplitBorrowMutResult);

    fn borrow(&'a self) -> Self::SplitBorrowResult {
        (Some(&self.0), self.1.borrow())
    }

    fn borrow_mut(&'a mut self) -> Self::SplitBorrowMutResult {
        (Some(&mut self.0), self.1.borrow_mut())
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

impl Named for () {
    #[inline]
    fn name(&self) -> &str {
        "Empty"
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
/// # Note
/// This operation may not be 100% accurate with Rust stable, see the notes for [`type_eq`]
/// (in `nightly`, it uses [specialization](https://stackoverflow.com/a/60138532/7658998)).
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
        log::info!("{x}");
    });

    tuple_for_each_mut!(f2, std::fmt::Display, t, |x| {
        log::info!("{x}");
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

#[cfg(test)]
mod test {
    #[cfg(feature = "alloc")]
    use crate::ownedref::OwnedMutSlice;
    use crate::tuples::type_eq;

    #[test]
    #[allow(unused_qualifications)] // for type name tests
    fn test_type_eq_simple() {
        // test eq
        assert!(type_eq::<u64, u64>());

        // test neq
        assert!(!type_eq::<u64, usize>());
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[allow(unused_qualifications)] // for type name tests
    fn test_type_eq() {
        // An alias for equality testing
        type OwnedMutSliceAlias<'a> = OwnedMutSlice<'a, u8>;

        // A function for lifetime testing
        #[allow(clippy::extra_unused_lifetimes)]
        fn test_lifetimes<'a, 'b>() {
            assert!(type_eq::<OwnedMutSlice<'a, u8>, OwnedMutSlice<'b, u8>>());
            assert!(type_eq::<OwnedMutSlice<'static, u8>, OwnedMutSlice<'a, u8>>());
            assert!(type_eq::<OwnedMutSlice<'a, u8>, OwnedMutSlice<'b, u8>>());
            assert!(type_eq::<OwnedMutSlice<'a, u8>, OwnedMutSlice<'static, u8>>());
            assert!(!type_eq::<OwnedMutSlice<'a, u8>, OwnedMutSlice<'b, i8>>());
        }
        assert!(type_eq::<OwnedMutSlice<u8>, OwnedMutSliceAlias>());

        test_lifetimes();
        // test weirder lifetime things
        assert!(type_eq::<OwnedMutSlice<u8>, OwnedMutSlice<u8>>());
        assert!(!type_eq::<OwnedMutSlice<u8>, OwnedMutSlice<u32>>());

        assert!(type_eq::<
            OwnedMutSlice<u8>,
            crate::ownedref::OwnedMutSlice<u8>,
        >());
        assert!(!type_eq::<
            OwnedMutSlice<u8>,
            crate::ownedref::OwnedMutSlice<u32>,
        >());
    }
}
