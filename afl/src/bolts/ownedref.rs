use alloc::{boxed::Box, vec::Vec};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug)]
pub enum Ptr<'a, T: 'a + ?Sized> {
    Ref(&'a T),
    Owned(Box<T>),
}

impl<'a, T: 'a + ?Sized + Serialize> Serialize for Ptr<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Ptr::Ref(r) => r.serialize(se),
            Ptr::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + ?Sized> Deserialize<'de> for Ptr<'a, T>
where
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(Ptr::Owned)
    }
}

impl<'a, T: Sized> Ptr<'a, T> {
    pub fn as_ref(&self) -> &T {
        match self {
            Ptr::Ref(r) => r,
            Ptr::Owned(v) => v.as_ref(),
        }
    }
}

pub enum PtrMut<'a, T: 'a + ?Sized> {
    Ref(&'a mut T),
    Owned(Box<T>),
}

impl<'a, T: 'a + ?Sized + Serialize> Serialize for PtrMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PtrMut::Ref(r) => r.serialize(se),
            PtrMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + ?Sized> Deserialize<'de> for PtrMut<'a, T>
where
    Box<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(PtrMut::Owned)
    }
}

impl<'a, T: Sized> PtrMut<'a, T> {
    pub fn as_ref(&self) -> &T {
        match self {
            PtrMut::Ref(r) => r,
            PtrMut::Owned(v) => v.as_ref(),
        }
    }

    pub fn as_mut(&mut self) -> &T {
        match self {
            PtrMut::Ref(r) => r,
            PtrMut::Owned(v) => v.as_mut(),
        }
    }
}

pub enum Slice<'a, T: 'a + Sized> {
    Ref(&'a [T]),
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for Slice<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Slice::Ref(r) => r.serialize(se),
            Slice::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for Slice<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(Slice::Owned)
    }
}

impl<'a, T: Sized> Slice<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Slice::Ref(r) => r,
            Slice::Owned(v) => v.as_slice(),
        }
    }
}

pub enum SliceMut<'a, T: 'a + Sized> {
    Ref(&'a mut [T]),
    Owned(Vec<T>),
}

impl<'a, T: 'a + Sized + Serialize> Serialize for SliceMut<'a, T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SliceMut::Ref(r) => r.serialize(se),
            SliceMut::Owned(b) => b.serialize(se),
        }
    }
}

impl<'de, 'a, T: 'a + Sized> Deserialize<'de> for SliceMut<'a, T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer).map(SliceMut::Owned)
    }
}

impl<'a, T: Sized> SliceMut<'a, T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &[T] {
        match self {
            SliceMut::Ref(r) => r,
            SliceMut::Owned(v) => v.as_mut_slice(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Cptr<T: Sized> {
    Cptr(*const T),
    Owned(Box<T>),
}

impl<T: Sized + Serialize> Serialize for Cptr<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(se)
    }
}

impl<'de, T: Sized + serde::de::DeserializeOwned> Deserialize<'de> for Cptr<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(Cptr::Owned)
    }
}

impl<T: Sized> Cptr<T> {
    pub fn as_ref(&self) -> &T {
        match self {
            Cptr::Cptr(p) => unsafe { p.as_ref().unwrap() },
            Cptr::Owned(v) => v.as_ref(),
        }
    }
}

pub enum CptrMut<T: Sized> {
    Cptr(*mut T),
    Owned(Box<T>),
}

impl<T: Sized + Serialize> Serialize for CptrMut<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_ref().serialize(se)
    }
}

impl<'de, T: Sized + serde::de::DeserializeOwned> Deserialize<'de> for CptrMut<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(CptrMut::Owned)
    }
}

impl<T: Sized> CptrMut<T> {
    pub fn as_ref(&self) -> &T {
        match self {
            CptrMut::Cptr(p) => unsafe { p.as_ref().unwrap() },
            CptrMut::Owned(b) => b.as_ref(),
        }
    }

    pub fn as_mut(&mut self) -> &mut T {
        match self {
            CptrMut::Cptr(p) => unsafe { p.as_mut().unwrap() },
            CptrMut::Owned(b) => b.as_mut(),
        }
    }
}

pub enum Array<T: Sized> {
    Cptr((*const T, usize)),
    Owned(Vec<T>),
}

impl<T: Sized + Serialize> Serialize for Array<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + Serialize> Deserialize<'de> for Array<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(Array::Owned)
    }
}

impl<T: Sized> Array<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            Array::Cptr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            Array::Owned(v) => v.as_slice(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ArrayMut<T: Sized> {
    Cptr((*mut T, usize)),
    Owned(Vec<T>),
}

impl<T: Sized + Serialize> Serialize for ArrayMut<T> {
    fn serialize<S>(&self, se: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(se)
    }
}

impl<'de, T: Sized + Serialize> Deserialize<'de> for ArrayMut<T>
where
    Vec<T>: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(de).map(ArrayMut::Owned)
    }
}

impl<T: Sized> ArrayMut<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            ArrayMut::Cptr(p) => unsafe { core::slice::from_raw_parts(p.0, p.1) },
            ArrayMut::Owned(v) => v.as_slice(),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        match self {
            ArrayMut::Cptr(p) => unsafe { core::slice::from_raw_parts_mut(p.0, p.1) },
            ArrayMut::Owned(v) => v.as_mut_slice(),
        }
    }
}
