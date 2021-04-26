//! Wrappers that abstracts references (or pointers) and owned data accesses.
// The serialization is towards owned, allowing to serialize pointers without troubles.

use alloc::{boxed::Box, vec::Vec};
use core::{clone::Clone, fmt::Debug};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wrap a reference and convert to a Box on serialize
#[derive(Clone, Debug)]
pub enum OwnedRef<'a, T>
where
    T: 'a + ?Sized,
{
    Ref(&'a T),
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

/// Wrap a mutable reference and convert to a Box on serialize
#[derive(Debug)]
pub enum OwnedRefMut<'a, T: 'a + ?Sized> {
    Ref(&'a mut T),
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

/// Wrap a slice and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedSlice<'a, T: 'a + Sized> {
    Ref(&'a [T]),
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
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedSlice::Ref(r) => r,
            OwnedSlice::Owned(v) => v.as_slice(),
        }
    }
}

/// Wrap a mutable slice and convert to a Vec on serialize
#[derive(Debug)]
pub enum OwnedSliceMut<'a, T: 'a + Sized> {
    Ref(&'a mut [T]),
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
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedSliceMut::Ref(r) => r,
            OwnedSliceMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &[T] {
        match self {
            OwnedSliceMut::Ref(r) => r,
            OwnedSliceMut::Owned(v) => v.as_mut_slice(),
        }
    }
}

/// Wrap a C-style pointer and convert to a Box on serialize
#[derive(Clone, Debug)]
pub enum OwnedPtr<T: Sized> {
    Ptr(*const T),
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

/// Wrap a C-style mutable pointer and convert to a Box on serialize
#[derive(Clone, Debug)]
pub enum OwnedPtrMut<T: Sized> {
    Ptr(*mut T),
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

/// Wrap a C-style pointer to an array (with size= and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedArrayPtr<T: Sized> {
    ArrayPtr((*const T, usize)),
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
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedArrayPtr::ArrayPtr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            OwnedArrayPtr::Owned(v) => v.as_slice(),
        }
    }
}

/// Wrap a C-style mutable pointer to an array (with size= and convert to a Vec on serialize
#[derive(Clone, Debug)]
pub enum OwnedArrayPtrMut<T: Sized> {
    ArrayPtr((*mut T, usize)),
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
    pub fn as_slice(&self) -> &[T] {
        match self {
            OwnedArrayPtrMut::ArrayPtr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            OwnedArrayPtrMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            OwnedArrayPtrMut::ArrayPtr(p) => unsafe { core::slice::from_raw_parts_mut(p.0, p.1) },
            OwnedArrayPtrMut::Owned(v) => v.as_mut_slice(),
        }
    }
}
