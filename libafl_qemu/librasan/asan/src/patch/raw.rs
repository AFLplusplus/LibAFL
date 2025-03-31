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
        debug!("patch - addr: {:#x}, target: {:#x}", target, destination);
        if target == destination {
            Err(RawPatchError::IdentityPatch(target))?;
        }
        let patch = Self::get_patch(destination)?;
        trace!("patch: {:02x?}", patch);
        let dest = unsafe { from_raw_parts_mut(target as *mut u8, patch.len()) };
        dest.copy_from_slice(&patch);
        Ok(())
    }
}

impl RawPatch {
    #[cfg(target_arch = "x86_64")]
    fn get_patch(destination: GuestAddr) -> Result<Vec<u8>, RawPatchError> {
        // mov rax, 0xdeadfacef00dd00d
        // jmp rax
        let insns = [
            [0x48, 0xb8, 0x0d, 0xd0, 0x0d, 0xf0, 0xce, 0xfa, 0xad, 0xde].to_vec(),
            [0xff, 0xe0].to_vec(),
        ];
        let addr = destination.to_le_bytes();
        let insn0_mod = [
            insns[0][0],
            insns[0][1],
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            addr[4],
            addr[5],
            addr[6],
            addr[7],
        ]
        .to_vec();
        let insns_mod = [&insn0_mod, &insns[1]];
        Ok(insns_mod.into_iter().flatten().cloned().collect())
    }

    #[cfg(target_arch = "x86")]
    fn get_patch(destination: GuestAddr) -> Result<Vec<u8>, RawPatchError> {
        // mov eax, 0xdeadface
        // jmp eax
        let insns = [
            [0xb8, 0xce, 0xfa, 0xad, 0xde].to_vec(),
            [0xff, 0xe0].to_vec(),
        ];
        let addr = destination.to_le_bytes();
        let insn0_mod = [insns[0][0], addr[0], addr[1], addr[2], addr[3]].to_vec();
        let insns_mod = [&insn0_mod, &insns[1]];
        Ok(insns_mod.into_iter().flatten().cloned().collect())
    }

    #[cfg(target_arch = "arm")]
    fn get_patch(destination: GuestAddr) -> Result<Vec<u8>, RawPatchError> {
        // ldr ip, [pc]
        // mov pc, ip
        // .long 0xdeadface
        let insns = [
            [0x00, 0xc0, 0x9f, 0xe5].to_vec(),
            [0x0c, 0xf0, 0xa0, 0xe1].to_vec(),
            [0xce, 0xfa, 0xad, 0xde].to_vec(),
        ];
        let addr = destination.to_ne_bytes().to_vec();
        let insns_mod = [&insns[0], &insns[1], &addr];
        Ok(insns_mod.into_iter().flatten().cloned().collect())
    }

    #[cfg(target_arch = "aarch64")]
    fn get_patch(destination: GuestAddr) -> Result<Vec<u8>, RawPatchError> {
        // ldr x16, #8
        // br  x16
        // .quad 0xdeadfacef00dd00d
        let insns = [
            [0x50, 0x00, 0x00, 0x58].to_vec(),
            [0x00, 0x02, 0x1f, 0xd6].to_vec(),
            [0x0d, 0xd0, 0x0d, 0xf0].to_vec(),
            [0xce, 0xfa, 0xad, 0xde].to_vec(),
        ];
        let addr = destination.to_ne_bytes().to_vec();
        let insns_mod = [&insns[0], &insns[1], &addr];
        Ok(insns_mod.into_iter().flatten().cloned().collect())
    }

    #[cfg(target_arch = "powerpc")]
    fn get_patch(destination: GuestAddr) -> Result<Vec<u8>, RawPatchError> {
        // lis 12, 0xdead
        // ori 12, 12, 0xface
        // mtctr 12
        // bctr
        let insns = [
            [0x3d, 0x80, 0xde, 0xad].to_vec(),
            [0x61, 0x8c, 0xfa, 0xce].to_vec(),
            [0x7d, 0x89, 0x03, 0xa6].to_vec(),
            [0x4e, 0x80, 0x04, 0x20].to_vec(),
        ];
        let addr = destination.to_be_bytes().to_vec();
        let insn0_mod = [insns[0][0], insns[0][1], addr[0], addr[1]].to_vec();
        let insn1_mod = [insns[1][0], insns[1][1], addr[2], addr[3]].to_vec();
        let insns_mod = [&insn0_mod, &insn1_mod, &insns[2], &insns[3]];
        Ok(insns_mod.into_iter().flatten().cloned().collect())
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum RawPatchError {
    #[error("Target and destination are the same: {0}")]
    IdentityPatch(GuestAddr),
}
