//! Poor-rust-man's downcasts to have `AnyMap`

use alloc::boxed::Box;
use core::{
    any::{Any, TypeId},
    mem::size_of,
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
        impl $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)? $crate::anymap::AsAny for $struct_name $(< $( $lt ),+ >)? {
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
/// # Note
/// Probably not safe for future compilers, fine for now.
/// The size changed in later rust versions, see <https://github.com/rust-lang/compiler-team/issues/608>
#[inline]
#[must_use]
#[allow(clippy::cast_ptr_alignment)]
pub const fn pack_type_id(id: u128) -> TypeId {
    match size_of::<TypeId>() {
        8 => {
            let id_64 = id as u64;
            // false positive: this branch only executes on 64 bit `TypeId`s
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                *(addr_of!(id_64) as *const TypeId)
            }
        }
        16 => unsafe { *(addr_of!(id) as *const TypeId) },
        _ => {
            // TypeId size of this size is not yet supported"
            panic!("Unsupported size for TypeId");
        }
    }
}

/// Unpack a `type_id` to an `u64`
/// Opposite of [`pack_type_id(id)`].
///
/// # Note
/// Probably not safe for future compilers, fine for now.
/// The size changed in later rust versions, see <https://github.com/rust-lang/compiler-team/issues/608>
#[inline]
#[must_use]
pub const fn unpack_type_id(id: TypeId) -> u128 {
    #[allow(clippy::cast_ptr_alignment)] // we never actually cast to u128 if the type is u64.
    match size_of::<TypeId>() {
        8 => unsafe { *(addr_of!(id) as *const u64) as u128 },
        16 => unsafe { *(addr_of!(id) as *const u128) },
        _ => {
            // TypeId size of this size is not yet supported"
            panic!("Unsupported size for TypeId");
        }
    }
}

#[cfg(test)]
mod test {
    use core::any::TypeId;

    use super::{pack_type_id, unpack_type_id};

    #[test]
    fn test_type_id() {
        let type_id_u64 = unpack_type_id(TypeId::of::<u64>());
        let type_id_u128 = unpack_type_id(TypeId::of::<u128>());

        assert_eq!(pack_type_id(type_id_u64), TypeId::of::<u64>());
        assert_eq!(pack_type_id(type_id_u128), TypeId::of::<u128>());

        assert_ne!(pack_type_id(type_id_u64), TypeId::of::<u128>());
        assert_ne!(pack_type_id(type_id_u128), TypeId::of::<u64>());
    }
}
