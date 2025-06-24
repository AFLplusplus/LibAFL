//! # raw
//! This implementation of patching performs modification by means of writing
//! the bytes of raw instructions into the target address
use alloc::vec::Vec;
use core::slice::from_raw_parts_mut;

use log::{debug, trace};
use thiserror::Error;

use crate::{GuestAddr, patch::Patch};

#[derive(Debug)]
pub struct RawPatch;

impl Patch for RawPatch {
    type Error = RawPatchError;
    fn patch(target: GuestAddr, destination: GuestAddr) -> Result<(), Self::Error> {
        debug!("patch - target: {target:#x}, destination: {destination:#x}");
        if target == destination {
            Err(RawPatchError::IdentityPatch(target))?;
        }
        let patch = Self::get_patch(target, destination);

        // Mask the thumb mode indicator bit
        #[cfg(target_arch = "arm")]
        let target = target & !1;

        trace!("patch: {patch:02x?}");
        let dest = unsafe { from_raw_parts_mut(target as *mut u8, patch.len()) };
        dest.copy_from_slice(&patch);
        Ok(())
    }
}

impl RawPatch {
    #[cfg(target_arch = "x86_64")]
    fn get_patch(_target: GuestAddr, destination: GuestAddr) -> Vec<u8> {
        // mov rax, 0xdeadfacef00dd00d
        // jmp rax
        let addr = destination.to_ne_bytes();
        #[rustfmt::skip]
        let insns: &[&[u8]] = &[
            &[0x48, 0xb8], &addr,
            &[0xff, 0xe0],
        ];
        insns.concat()
    }

    #[cfg(target_arch = "x86")]
    fn get_patch(_target: GuestAddr, destination: GuestAddr) -> Vec<u8> {
        // mov eax, 0xdeadface
        // jmp eax
        let addr = destination.to_ne_bytes();
        #[rustfmt::skip]
        let insns: &[&[u8]] = &[
            &[0xb8], &addr,
            &[0xff, 0xe0],
        ];
        insns.concat()
    }

    #[cfg(target_arch = "arm")]
    fn get_patch(target: GuestAddr, destination: GuestAddr) -> Vec<u8> {
        let addr = destination.to_ne_bytes();
        // If our target is in thumb mode
        #[rustfmt::skip]
        let insns: &[&[u8]] = if target & 1 == 1 {
            // ldr ip, [pc, #2]
            // bx ip
            // .long 0xdeadface
            &[
                &[0xdf, 0xf8, 0x02, 0xc0],
                &[0x60, 0x47],
                &addr,
            ]
        } else {
            // ldr ip, [pc]
            // bx ip
            // .long 0xdeadface
            &[
                &[0x00, 0xc0, 0x9f, 0xe5],
                &[0x1c, 0xff, 0x2f, 0xe1],
                &addr,
            ]
        };
        insns.concat()
    }

    #[cfg(target_arch = "aarch64")]
    fn get_patch(_target: GuestAddr, destination: GuestAddr) -> Vec<u8> {
        // ldr x16, #8
        // br  x16
        // .quad 0xdeadfacef00dd00d
        let addr = destination.to_ne_bytes();
        #[rustfmt::skip]
        let insns: &[&[u8]] = &[
            &[0x50, 0x00, 0x00, 0x58],
            &[0x00, 0x02, 0x1f, 0xd6],
            &addr
        ];
        insns.concat()
    }

    #[cfg(target_arch = "powerpc")]
    fn get_patch(_target: GuestAddr, destination: GuestAddr) -> Vec<u8> {
        // lis 12, 0xdead
        // ori 12, 12, 0xface
        // mtctr 12
        // bctr
        let addr = destination.to_ne_bytes();
        #[rustfmt::skip]
        let insns: &[&[u8]] = &[
            &[0x3d, 0x80], &addr[..2],
            &[0x61, 0x8c], &addr[2..],
            &[0x7d, 0x89, 0x03, 0xa6],
            &[0x4e, 0x80, 0x04, 0x20],
        ];
        insns.concat()
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum RawPatchError {
    #[error("Target and destination are the same: {0}")]
    IdentityPatch(GuestAddr),
}
