//! Wrappers that abstracts references (or pointers) and owned data accesses.
// The serialization is towards owned, allowing to serialize pointers without troubles.

use crate::bolts::{AsMutSlice, AsSlice};
use alloc::{
    boxed::Box,
    slice::{Iter, IterMut},
    vec::Vec,
};
use core::{clone::Clone, fmt::Debug, slice};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Trait to convert into an Owned type
pub trait IntoOwned {
    /// Returns if the current type is an owned type.
    #[must_use]
    fn is_owned(&self) -> bool;

    /// Transfer the current type into an owned type.
    #[must_use]
    fn into_owned(self) -> Self;
}

/// Wrap a reference and convert to a [`Box`] on serialize
#[derive(Clone, Debug)]
pub enum OwnedRef<'a, T>
where
    T: 'a + ?Sized,
{
    /// A ref to a type
    Ref(&'a T),
    /// An owned [`Box`] of a type
    Owned(Box<T>),
}

impl<'a, T> Serialize for OwnedRef<'a, T>
where
    T: 'a + ?Sized + Serialize,
{
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedRef::Ref(r) => r.serialize(se),
            OwnedRef::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T> Deserialize<'de> for OwnedRef<'a, T>
where
    T: 'a + ?Sized,
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedRef::Owned)
    }
}

impl<'a, T> AsRef<T> for OwnedRef<'a, T>
where
    T: Sized,
{
    #[must_use]
    fn as_ref(&self) -> &T {
        match self {
            OwnedRef::Ref(r) => r,
            OwnedRef::Owned(v) => v.as_ref(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedRef<'a, T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self {
            OwnedRef::Ref(_) => false,
            OwnedRef::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        match self {
            OwnedRef::Ref(r) => OwnedRef::Owned(Box::new(r.clone())),
            OwnedRef::Owned(v) => OwnedRef::Owned(v),
        }
    }
}

/// Wrap a mutable reference and convert to a Box on serialize
#[derive(Debug)]
pub enum OwnedRefMut<'a, T: 'a + ?Sized> {
    /// A mutable ref to a type
    Ref(&'a mut T),
    /// An owned [`Box`] of a type
    Owned(Box<T>),
}

impl<'a, T: 'a + ?Sized + Serialize> Serialize for OwnedRefMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedRefMut::Ref(r) => r.serialize(se),
            OwnedRefMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + ?Sized> Deserialize<'de> for OwnedRefMut<'a, T>
where
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedRefMut::Owned)
    }
}

impl<'a, T: Sized> AsRef<T> for OwnedRefMut<'a, T> {
    #[must_use]
    fn as_ref(&self) -> &T {
        match self {
            OwnedRefMut::Ref(r) => r,
            OwnedRefMut::Owned(v) => v.as_ref(),
        }
    }
}

impl<'a, T: Sized> AsMut<T> for OwnedRefMut<'a, T> {
    #[must_use]
    fn as_mut(&mut self) -> &mut T {
        match self {
            OwnedRefMut::Ref(r) => r,
            OwnedRefMut::Owned(v) => v.as_mut(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedRefMut<'a, T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self {
            OwnedRefMut::Ref(_) => false,
            OwnedRefMut::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        match self {
            OwnedRefMut::Ref(r) => OwnedRefMut::Owned(Box::new(r.clone())),
            OwnedRefMut::Owned(v) => OwnedRefMut::Owned(v),
        }
    }
}

/// Wrap a slice and convert to a Vec on serialize
#[derive(Clone, Debug)]
enum OwnedSliceInner<'a, T: 'a + Sized> {
    /// A ref to a raw slice and length
    RefRaw(*const T, usize),
    /// A ref to a slice
    Ref(&'a [T]),
    /// A ref to an owned [`Vec`]
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for OwnedSliceInner<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedSliceInner::RefRaw(rr, len) => unsafe {
                slice::from_raw_parts(*rr, *len).serialize(se)
            },
            OwnedSliceInner::Ref(r) => r.serialize(se),
            OwnedSliceInner::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for OwnedSliceInner<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedSliceInner::Owned)
    }
}

/// Wrap a slice and convert to a Vec on serialize.
/// We use a hidden inner enum so the public API can be safe,
/// unless the user uses the unsafe [`OwnedSlice::from_raw_parts`]
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedSlice<'a, T: 'a + Sized> {
    inner: OwnedSliceInner<'a, T>,
}

impl<'a, T: 'a + Clone> Clone for OwnedSlice<'a, T> {
    fn clone(&self) -> Self {
        Self {
            inner: OwnedSliceInner::Owned(self.as_slice().to_vec()),
        }
    }
}

impl<'a, T> OwnedSlice<'a, T> {
    /// Create a new [`OwnedSlice`] from a raw pointer and length
    ///
    /// # Safety
    ///
    /// The pointer must be valid and point to a map of the size `size_of<T>() * len`
    /// The contents will be dereferenced in subsequent operations.
    #[must_use]
    pub unsafe fn from_raw_parts(ptr: *const T, len: usize) -> Self {
        Self {
            inner: OwnedSliceInner::RefRaw(ptr, len),
        }
    }
}

impl<'a, 'it, T> IntoIterator for &'it OwnedSlice<'a, T> {
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Iter<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// Create a new [`OwnedSlice`] from a vector
impl<'a, T> From<Vec<T>> for OwnedSlice<'a, T> {
    fn from(vec: Vec<T>) -> Self {
        Self {
            inner: OwnedSliceInner::Owned(vec),
        }
    }
}

/// Create a new [`OwnedSlice`] from a vector reference
impl<'a, T> From<&'a Vec<T>> for OwnedSlice<'a, T> {
    fn from(vec: &'a Vec<T>) -> Self {
        Self {
            inner: OwnedSliceInner::Ref(vec),
        }
    }
}

/// Create a new [`OwnedSlice`] from a reference to a slice
impl<'a, T> From<&'a [T]> for OwnedSlice<'a, T> {
    fn from(r: &'a [T]) -> Self {
        Self {
            inner: OwnedSliceInner::Ref(r),
        }
    }
}

/// Create a new [`OwnedSlice`] from a [`OwnedSliceMut`]
impl<'a, T> From<OwnedSliceMut<'a, T>> for OwnedSlice<'a, T> {
    fn from(mut_slice: OwnedSliceMut<'a, T>) -> Self {
        Self {
            inner: match mut_slice.inner {
                OwnedSliceMutInner::RefRaw(ptr, len) => OwnedSliceInner::RefRaw(ptr as _, len),
                OwnedSliceMutInner::Ref(r) => OwnedSliceInner::Ref(r as _),
                OwnedSliceMutInner::Owned(v) => OwnedSliceInner::Owned(v),
            },
        }
    }
}

impl<'a, T: Sized> AsSlice<T> for OwnedSlice<'a, T> {
    /// Get the [`OwnedSlice`] as slice.
    #[must_use]
    fn as_slice(&self) -> &[T] {
        match &self.inner {
            OwnedSliceInner::Ref(r) => r,
            OwnedSliceInner::RefRaw(rr, len) => unsafe { slice::from_raw_parts(*rr, *len) },
            OwnedSliceInner::Owned(v) => v.as_slice(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedSlice<'a, T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self.inner {
            OwnedSliceInner::RefRaw(_, _) | OwnedSliceInner::Ref(_) => false,
            OwnedSliceInner::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        match self.inner {
            OwnedSliceInner::RefRaw(rr, len) => Self {
                inner: OwnedSliceInner::Owned(unsafe { slice::from_raw_parts(rr, len).to_vec() }),
            },
            OwnedSliceInner::Ref(r) => Self {
                inner: OwnedSliceInner::Owned(r.to_vec()),
            },
            OwnedSliceInner::Owned(v) => Self {
                inner: OwnedSliceInner::Owned(v),
            },
        }
    }
}

/// Wrap a mutable slice and convert to a Vec on serialize.
/// We use a hidden inner enum so the public API can be safe,
/// unless the user uses the unsafe [`OwnedSliceMut::from_raw_parts_mut`]
#[derive(Debug)]
pub enum OwnedSliceMutInner<'a, T: 'a + Sized> {
    /// A raw ptr to a memory location and a length
    RefRaw(*mut T, usize),
    /// A ptr to a mutable slice of the type
    Ref(&'a mut [T]),
    /// An owned [`Vec`] of the type
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for OwnedSliceMutInner<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedSliceMutInner::RefRaw(rr, len) => {
                unsafe { slice::from_raw_parts_mut(*rr, *len) }.serialize(se)
            }
            OwnedSliceMutInner::Ref(r) => r.serialize(se),
            OwnedSliceMutInner::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for OwnedSliceMutInner<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedSliceMutInner::Owned)
    }
}

/// Wrap a mutable slice and convert to a Vec on serialize
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnedSliceMut<'a, T: 'a + Sized> {
    inner: OwnedSliceMutInner<'a, T>,
}

impl<'a, 'it, T> IntoIterator for &'it mut OwnedSliceMut<'a, T> {
    type Item = <IterMut<'it, T> as Iterator>::Item;
    type IntoIter = IterMut<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_mut_slice().iter_mut()
    }
}

impl<'a, 'it, T> IntoIterator for &'it OwnedSliceMut<'a, T> {
    type Item = <Iter<'it, T> as Iterator>::Item;
    type IntoIter = Iter<'it, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<'a, T: 'a + Sized> OwnedSliceMut<'a, T> {
    /// Create a new [`OwnedSliceMut`] from a raw pointer and length
    ///
    /// # Safety
    ///
    /// The pointer must be valid and point to a map of the size `size_of<T>() * len`
    /// The contents will be dereferenced in subsequent operations.
    #[must_use]
    pub unsafe fn from_raw_parts_mut(ptr: *mut T, len: usize) -> OwnedSliceMut<'a, T> {
        if ptr.is_null() || len == 0 {
            Self {
                inner: OwnedSliceMutInner::Owned(Vec::new()),
            }
        } else {
            Self {
                inner: OwnedSliceMutInner::RefRaw(ptr, len),
            }
        }
    }
}

impl<'a, T: Sized> AsSlice<T> for OwnedSliceMut<'a, T> {
    /// Get the value as slice
    #[must_use]
    fn as_slice(&self) -> &[T] {
        match &self.inner {
            OwnedSliceMutInner::RefRaw(rr, len) => unsafe { slice::from_raw_parts(*rr, *len) },
            OwnedSliceMutInner::Ref(r) => r,
            OwnedSliceMutInner::Owned(v) => v.as_slice(),
        }
    }
}
impl<'a, T: Sized> AsMutSlice<T> for OwnedSliceMut<'a, T> {
    /// Get the value as mut slice
    #[must_use]
    fn as_mut_slice(&mut self) -> &mut [T] {
        match &mut self.inner {
            OwnedSliceMutInner::RefRaw(rr, len) => unsafe { slice::from_raw_parts_mut(*rr, *len) },
            OwnedSliceMutInner::Ref(r) => r,
            OwnedSliceMutInner::Owned(v) => v.as_mut_slice(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedSliceMut<'a, T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self.inner {
            OwnedSliceMutInner::RefRaw(_, _) | OwnedSliceMutInner::Ref(_) => false,
            OwnedSliceMutInner::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        let vec = match self.inner {
            OwnedSliceMutInner::RefRaw(rr, len) => unsafe {
                slice::from_raw_parts_mut(rr, len).to_vec()
            },
            OwnedSliceMutInner::Ref(r) => r.to_vec(),
            OwnedSliceMutInner::Owned(v) => v,
        };
        Self {
            inner: OwnedSliceMutInner::Owned(vec),
        }
    }
}

impl<'a, T: 'a + Clone> Clone for OwnedSliceMut<'a, T> {
    fn clone(&self) -> Self {
        Self {
            inner: OwnedSliceMutInner::Owned(self.as_slice().to_vec()),
        }
    }
}

/// Create a new [`OwnedSliceMut`] from a vector
impl<'a, T> From<Vec<T>> for OwnedSliceMut<'a, T> {
    fn from(vec: Vec<T>) -> Self {
        Self {
            inner: OwnedSliceMutInner::Owned(vec),
        }
    }
}

/// Create a new [`OwnedSliceMut`] from a vector reference
impl<'a, T> From<&'a mut Vec<T>> for OwnedSliceMut<'a, T> {
    fn from(vec: &'a mut Vec<T>) -> Self {
        Self {
            inner: OwnedSliceMutInner::Ref(vec),
        }
    }
}

/// Create a new [`OwnedSliceMut`] from a reference to ref to a slice
impl<'a, T> From<&'a mut [T]> for OwnedSliceMut<'a, T> {
    fn from(r: &'a mut [T]) -> Self {
        Self {
            inner: OwnedSliceMutInner::Ref(r),
        }
    }
}

/// Create a new [`OwnedSliceMut`] from a reference to ref to a slice
#[allow(clippy::mut_mut)] // This makes use in some iterators easier
impl<'a, T> From<&'a mut &'a mut [T]> for OwnedSliceMut<'a, T> {
    fn from(r: &'a mut &'a mut [T]) -> Self {
        Self {
            inner: OwnedSliceMutInner::Ref(r),
        }
    }
}

/// Wrap a C-style pointer and convert to a Box on serialize
#[derive(Clone, Debug)]
pub enum OwnedPtr<T: Sized> {
    /// Ptr to the content
    Ptr(*const T),
    /// Ptr to an owned [`Box`] of the content.
    Owned(Box<T>),
}

impl<T: Sized + Serialize> Serialize for OwnedPtr<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(se)
    }
}

impl<'de, T: Sized + serde::de::DeserializeOwned> Deserialize<'de> for OwnedPtr<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(OwnedPtr::Owned)
    }
}

impl<T: Sized> AsRef<T> for OwnedPtr<T> {
    #[must_use]
    fn as_ref(&self) -> &T {
        match self {
            OwnedPtr::Ptr(p) => unsafe { p.as_ref().unwrap() },
            OwnedPtr::Owned(v) => v.as_ref(),
        }
    }
}

impl<T> IntoOwned for OwnedPtr<T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self {
            OwnedPtr::Ptr(_) => false,
            OwnedPtr::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        match self {
            OwnedPtr::Ptr(p) => unsafe { OwnedPtr::Owned(Box::new(p.as_ref().unwrap().clone())) },
            OwnedPtr::Owned(v) => OwnedPtr::Owned(v),
        }
    }
}

/// Wrap a C-style mutable pointer and convert to a Box on serialize
#[derive(Clone, Debug)]
pub enum OwnedPtrMut<T: Sized> {
    /// A mut ptr to the content
    Ptr(*mut T),
    /// An owned [`Box`] to the content
    Owned(Box<T>),
}

impl<T: Sized + Serialize> Serialize for OwnedPtrMut<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(se)
    }
}

impl<'de, T: Sized + serde::de::DeserializeOwned> Deserialize<'de> for OwnedPtrMut<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(OwnedPtrMut::Owned)
    }
}

impl<T: Sized> AsRef<T> for OwnedPtrMut<T> {
    #[must_use]
    fn as_ref(&self) -> &T {
        match self {
            OwnedPtrMut::Ptr(p) => unsafe { p.as_ref().unwrap() },
            OwnedPtrMut::Owned(b) => b.as_ref(),
        }
    }
}

impl<T: Sized> AsMut<T> for OwnedPtrMut<T> {
    fn as_mut(&mut self) -> &mut T {
        match self {
            OwnedPtrMut::Ptr(p) => unsafe { p.as_mut().unwrap() },
            OwnedPtrMut::Owned(b) => b.as_mut(),
        }
    }
}

impl<T> IntoOwned for OwnedPtrMut<T>
where
    T: Sized + Clone,
{
    #[must_use]
    fn is_owned(&self) -> bool {
        match self {
            OwnedPtrMut::Ptr(_) => false,
            OwnedPtrMut::Owned(_) => true,
        }
    }

    #[must_use]
    fn into_owned(self) -> Self {
        match self {
            OwnedPtrMut::Ptr(p) => unsafe {
                OwnedPtrMut::Owned(Box::new(p.as_ref().unwrap().clone()))
            },
            OwnedPtrMut::Owned(v) => OwnedPtrMut::Owned(v),
        }
    }
}
