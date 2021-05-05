//! Wrappers that abstracts references (or pointers) and owned data accesses.
// The serialization is towards owned, allowing to serialize pointers without troubles.

use alloc::{boxed::Box, vec::Vec};
use core::{clone::Clone, fmt::Debug};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Trait to convert into an Owned type
pub trait IntoOwned {
    /// Returns if the current type is an owned type.
    fn is_owned(&self) -> bool;

    /// Transfer the current type into an owned type.
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
    fn is_owned(&self) -> bool {
        match self {
            OwnedRef::Ref(_) => false,
            OwnedRef::Owned(_) => true,
        }
    }

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
    fn as_ref(&self) -> &T {
        match self {
            OwnedRefMut::Ref(r) => r,
            OwnedRefMut::Owned(v) => v.as_ref(),
        }
    }
}

impl<'a, T: Sized> AsMut<T> for OwnedRefMut<'a, T> {
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
    fn is_owned(&self) -> bool {
        match self {
            OwnedRefMut::Ref(_) => false,
            OwnedRefMut::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedRefMut::Ref(r) => OwnedRefMut::Owned(Box::new(r.clone())),
            OwnedRefMut::Owned(v) => OwnedRefMut::Owned(v),
        }
    }
}

/// Wrap a slice and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedSlice<'a, T: 'a + Sized> {
    /// A ref to a slice
    Ref(&'a [T]),
    /// A ref to an owned [`Vec`]
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for OwnedSlice<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedSlice::Ref(r) => r.serialize(se),
            OwnedSlice::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for OwnedSlice<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedSlice::Owned)
    }
}

impl<'a, T: Sized> OwnedSlice<'a, T> {
    /// Get the [`OwnedSlice`] as slice.
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedSlice::Ref(r) => r,
            OwnedSlice::Owned(v) => v.as_slice(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedSlice<'a, T>
where
    T: Sized + Clone,
{
    fn is_owned(&self) -> bool {
        match self {
            OwnedSlice::Ref(_) => false,
            OwnedSlice::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedSlice::Ref(r) => OwnedSlice::Owned(r.to_vec()),
            OwnedSlice::Owned(v) => OwnedSlice::Owned(v),
        }
    }
}

/// Wrap a mutable slice and convert to a Vec on serialize
#[derive(Debug)]
pub enum OwnedSliceMut<'a, T: 'a + Sized> {
    /// A ptr to a mutable slice of the type
    Ref(&'a mut [T]),
    /// An owned [`Vec`] of the type
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for OwnedSliceMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OwnedSliceMut::Ref(r) => r.serialize(se),
            OwnedSliceMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for OwnedSliceMut<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(OwnedSliceMut::Owned)
    }
}

impl<'a, T: Sized> OwnedSliceMut<'a, T> {
    /// Get the value as slice
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedSliceMut::Ref(r) => r,
            OwnedSliceMut::Owned(v) => v.as_slice(),
        }
    }

    /// Get the value as mut slice
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            OwnedSliceMut::Ref(r) => r,
            OwnedSliceMut::Owned(v) => v.as_mut_slice(),
        }
    }
}

impl<'a, T> IntoOwned for OwnedSliceMut<'a, T>
where
    T: Sized + Clone,
{
    fn is_owned(&self) -> bool {
        match self {
            OwnedSliceMut::Ref(_) => false,
            OwnedSliceMut::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedSliceMut::Ref(r) => OwnedSliceMut::Owned(r.to_vec()),
            OwnedSliceMut::Owned(v) => OwnedSliceMut::Owned(v),
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
    fn is_owned(&self) -> bool {
        match self {
            OwnedPtr::Ptr(_) => false,
            OwnedPtr::Owned(_) => true,
        }
    }

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
    fn is_owned(&self) -> bool {
        match self {
            OwnedPtrMut::Ptr(_) => false,
            OwnedPtrMut::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedPtrMut::Ptr(p) => unsafe {
                OwnedPtrMut::Owned(Box::new(p.as_ref().unwrap().clone()))
            },
            OwnedPtrMut::Owned(v) => OwnedPtrMut::Owned(v),
        }
    }
}

/// Wrap a C-style pointer to an array (with size) and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedArrayPtr<T: Sized> {
    /// Ptr to a slice
    ArrayPtr((*const T, usize)),
    /// A owned [`Vec`].
    Owned(Vec<T>),
}

impl<T: Sized + Serialize> Serialize for OwnedArrayPtr<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + Serialize> Deserialize<'de> for OwnedArrayPtr<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(OwnedArrayPtr::Owned)
    }
}

impl<T: Sized> OwnedArrayPtr<T> {
    /// Get a slice from this array.
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedArrayPtr::ArrayPtr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            OwnedArrayPtr::Owned(v) => v.as_slice(),
        }
    }
}

impl<T> IntoOwned for OwnedArrayPtr<T>
where
    T: Sized + Clone,
{
    fn is_owned(&self) -> bool {
        match self {
            OwnedArrayPtr::ArrayPtr(_) => false,
            OwnedArrayPtr::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedArrayPtr::ArrayPtr(p) => unsafe {
                OwnedArrayPtr::Owned(core::slice::from_raw_parts(p.0, p.1).to_vec())
            },
            OwnedArrayPtr::Owned(v) => OwnedArrayPtr::Owned(v),
        }
    }
}

/// Wrap a C-style mutable pointer to an array (with size) and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedArrayPtrMut<T: Sized> {
    /// A ptr to the array (or slice).
    ArrayPtr((*mut T, usize)),
    /// An owned [`Vec`].
    Owned(Vec<T>),
}

impl<T: Sized + Serialize> Serialize for OwnedArrayPtrMut<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + Serialize> Deserialize<'de> for OwnedArrayPtrMut<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(OwnedArrayPtrMut::Owned)
    }
}

impl<T: Sized> OwnedArrayPtrMut<T> {
    /// Return this array as slice
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedArrayPtrMut::ArrayPtr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            OwnedArrayPtrMut::Owned(v) => v.as_slice(),
        }
    }

    /// Return this array as mut slice
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            OwnedArrayPtrMut::ArrayPtr(p) => unsafe { core::slice::from_raw_parts_mut(p.0, p.1) },
            OwnedArrayPtrMut::Owned(v) => v.as_mut_slice(),
        }
    }
}

impl<T> IntoOwned for OwnedArrayPtrMut<T>
where
    T: Sized + Clone,
{
    fn is_owned(&self) -> bool {
        match self {
            OwnedArrayPtrMut::ArrayPtr(_) => false,
            OwnedArrayPtrMut::Owned(_) => true,
        }
    }

    fn into_owned(self) -> Self {
        match self {
            OwnedArrayPtrMut::ArrayPtr(p) => unsafe {
                OwnedArrayPtrMut::Owned(core::slice::from_raw_parts(p.0, p.1).to_vec())
            },
            OwnedArrayPtrMut::Owned(v) => OwnedArrayPtrMut::Owned(v),
        }
    }
}
