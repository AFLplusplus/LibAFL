//! # guest
//! Performs memory tracking by allocating the high and low shadow regions and
//! mapping them into the guest memory space. All of the operations of this
//! module are performed by reading or writing these shadow regions.
use alloc::fmt::Debug;
use core::marker::PhantomData;

use log::{debug, trace};
use thiserror::Error;

use crate::{
    GuestAddr,
    mmap::Mmap,
    shadow::{PoisonType, Shadow},
};

#[allow(dead_code)]
#[derive(Debug)]
pub struct GuestShadow<M: Mmap, L: ShadowLayout> {
    lo: M,
    hi: M,
    _phantom: PhantomData<L>,
}

impl<M: Mmap, L: ShadowLayout> Shadow for GuestShadow<M, L> {
    type Error = GuestShadowError<M>;

    fn load(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("load - start: {start:#x}, len: {len:#x}");
        if self.is_poison(start, len)? {
            Err(GuestShadowError::Poisoned(start, len))
        } else {
            Ok(())
        }
    }

    fn store(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("store - start: {start:#x}, len: {len:#x}");
        if self.is_poison(start, len)? {
            Err(GuestShadowError::Poisoned(start, len))
        } else {
            Ok(())
        }
    }

    fn poison(
        &mut self,
        start: GuestAddr,
        len: usize,
        poison: PoisonType,
    ) -> Result<(), Self::Error> {
        debug!("poison - start: {start:#x}, len: {len:#x}, poison: {poison:?}",);

        if Self::is_out_of_bounds(start, len) {
            Err(GuestShadowError::AddressRangeOverflow(start, len))?;
        }

        if !Self::is_memory(start, len) {
            Err(GuestShadowError::InvalidMemoryAddress(start))?;
        }

        if !Self::is_end_aligned(start, len) {
            Err(GuestShadowError::UnalignedEndAddress(start, len))?;
        }

        if len == 0 {
            return Ok(());
        }

        let mut remaining_len = len;

        /* First poison any odd bytes from the unaligned start of the region */
        if !Self::is_start_aligned(start) {
            let first_unpoisoned = Self::remainder(start);
            let poisoned = Self::ALLOC_ALIGN_SIZE - first_unpoisoned;
            remaining_len -= poisoned;

            let start_aligned_down = Self::align_down(start);
            let first_shadow = self.get_shadow_mut(start_aligned_down, Self::ALLOC_ALIGN_SIZE)?;
            first_shadow[0] = first_unpoisoned as u8;
        }

        /* If our range is expressed within the first byte, then we are done here */
        if remaining_len == 0 {
            return Ok(());
        }

        /* Now poison the rest of the range, then end is aligned */
        let start_aligned_up = Self::align_up(start);
        let shadow_map = self.get_shadow_mut(start_aligned_up, remaining_len)?;
        shadow_map.iter_mut().for_each(|v| *v = poison as u8);

        Ok(())
    }

    fn unpoison(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        debug!("unpoison - start: {start:#x}, len: {len:#x}");

        if Self::is_out_of_bounds(start, len) {
            Err(GuestShadowError::AddressRangeOverflow(start, len))?;
        }

        if !Self::is_memory(start, len) {
            Err(GuestShadowError::InvalidMemoryAddress(start))?;
        }

        if !Self::is_start_aligned(start) {
            Err(GuestShadowError::UnalignedStartAddress(start, len))?;
        }

        if len == 0 {
            return Ok(());
        }

        let mut remaining_len = len;

        let aligned_len = Self::align_down(len);

        /* Handle the unaligned end of the region */
        if !Self::is_end_aligned(start, len) {
            let end_aligned = start + aligned_len;
            let last_unpoisoned = Self::remainder(len);
            remaining_len -= last_unpoisoned;

            let last_shadow = self.get_shadow_mut(end_aligned, Self::ALLOC_ALIGN_SIZE)?;
            last_shadow[0] = last_unpoisoned as u8;
        }

        /* If our region is just the unaligned end, then we are done here */
        if remaining_len == 0 {
            return Ok(());
        }

        /*
         * Next unpoison the aligned portion of our allocation (the start
         * is aligned, but the end is not)
         */
        let shadow_map = self.get_shadow_mut(start, aligned_len)?;
        shadow_map
            .iter_mut()
            .for_each(|v| *v = PoisonType::AsanValid as u8);

        Ok(())
    }

    fn is_poison(&self, start: GuestAddr, len: usize) -> Result<bool, Self::Error> {
        debug!("is_poison - start: {start:#x}, len: {len:#x}");

        if Self::is_out_of_bounds(start, len) {
            Err(GuestShadowError::AddressRangeOverflow(start, len))?;
        }

        if !Self::is_memory(start, len) {
            Err(GuestShadowError::InvalidMemoryAddress(start))?;
        }

        if len == 0 {
            return Ok(false);
        }

        let mut remaining_len = len;

        /* If our start is unaligned */
        if !Self::is_start_aligned(start) {
            /* How many bytes represented by the first shadow byte should be ignored */
            let skipped = Self::remainder(start);

            /* How many bytes from our region are represented by the first shadow byte */
            let first_len = Self::ALLOC_ALIGN_SIZE - skipped;

            let k_start = self.get_shadow(Self::align_down(start), Self::ALLOC_ALIGN_SIZE)?;
            let first_k = k_start[0] as i8;

            /* If our buffer ends within the first shadow byte */
            if len <= first_len {
                /*
                 * The length we must test is the length we have skipped (due to the
                 * unaligned start) plus the length of our buffer
                 */
                let test_len = (len + skipped) as i8;
                if first_k != 0 && test_len > first_k {
                    trace!(
                        "is_poison #1 - start: {start:#x}, len: {len:#x}, first_k: {first_k:#x}, first_len: {test_len:#x}",
                    );
                    return Ok(true);
                } else {
                    trace!(
                        "!is_poison #1 - start: {start:#x}, len: {len:#x}, first_k: {first_k:#x}, first_len: {test_len:#x}",
                    );
                    return Ok(false);
                }
            }

            remaining_len -= first_len;

            /*
             * If our buffer extends beyond the first shadow byte, then it must be
             * zero
             */
            if first_k != 0 {
                trace!("is_poison #2 - start: {start:#x}, len: {len:#x}, first_k: {first_k:#x}",);
                return Ok(true);
            }
        }

        /* If our end is unaligned */
        if !Self::is_end_aligned(start, len) {
            let last_len = Self::end_remainder(start, len);
            remaining_len -= last_len;

            let k_end = self.get_shadow(Self::align_down(start + len), Self::ALLOC_ALIGN_SIZE)?;

            let last_k = k_end[0] as i8;
            if last_k != 0 && last_len as i8 > last_k {
                trace!(
                    "is_poison #3 - start: {start:#x}, len: {len:#x}, last_k: {last_k:#x}, last_len: {last_len:#x}",
                );
                return Ok(true);
            }
        }

        /*
         * If we have accounted for the length of our region only using the unaligned start and end
         */
        if remaining_len == 0 {
            return Ok(false);
        }

        let start_aligned = Self::align_up(start);

        let shadow_map = self.get_shadow(start_aligned, remaining_len)?;

        let poisoned = shadow_map.iter().any(|v| *v != PoisonType::AsanValid as u8);

        if poisoned {
            trace!(
                "is_poison #4 - start_aligned: {start_aligned:#x}, remaining_len: {remaining_len:#x}",
            );
            Ok(true)
        } else {
            trace!(
                "!is_poison #4 - start_aligned: {start_aligned:#x}, remaining_len: {remaining_len:#x}",
            );
            Ok(false)
        }
    }
}

impl<M: Mmap, L: ShadowLayout> GuestShadow<M, L> {
    pub const SHADOW_OFFSET: usize = L::SHADOW_OFFSET;
    pub const LOW_MEM_OFFSET: GuestAddr = L::LOW_MEM_OFFSET;
    pub const LOW_MEM_SIZE: usize = L::LOW_MEM_SIZE;
    pub const LOW_SHADOW_OFFSET: GuestAddr = L::LOW_SHADOW_OFFSET;
    pub const LOW_SHADOW_SIZE: usize = L::LOW_SHADOW_SIZE;
    pub const HIGH_SHADOW_OFFSET: GuestAddr = L::HIGH_SHADOW_OFFSET;
    pub const HIGH_SHADOW_SIZE: usize = L::HIGH_SHADOW_SIZE;
    pub const HIGH_MEM_OFFSET: GuestAddr = L::HIGH_MEM_OFFSET;
    pub const HIGH_MEM_SIZE: usize = L::HIGH_MEM_SIZE;

    pub const ALLOC_ALIGN_POW: usize = L::ALLOC_ALIGN_POW;
    pub const ALLOC_ALIGN_SIZE: usize = L::ALLOC_ALIGN_SIZE;

    pub const LOW_MEM_LIMIT: usize = L::LOW_MEM_OFFSET + (L::LOW_MEM_SIZE - 1);
    pub const LOW_SHADOW_LIMIT: usize = L::LOW_SHADOW_OFFSET + (L::LOW_SHADOW_SIZE - 1);
    pub const HIGH_SHADOW_LIMIT: usize = L::HIGH_SHADOW_OFFSET + (L::HIGH_SHADOW_SIZE - 1);
    pub const HIGH_MEM_LIMIT: usize = L::HIGH_MEM_OFFSET + (L::HIGH_MEM_SIZE - 1);

    pub fn new() -> Result<GuestShadow<M, L>, GuestShadowError<M>> {
        trace!(
            "Mapping low shadow: {:#x}-{:#x}",
            Self::LOW_SHADOW_OFFSET,
            Self::LOW_SHADOW_OFFSET + Self::LOW_SHADOW_SIZE
        );
        let lo = Self::map_shadow(Self::LOW_SHADOW_OFFSET, Self::LOW_SHADOW_SIZE)
            .map_err(|e| GuestShadowError::MmapError(e))?;
        trace!(
            "Mapping high shadow: {:#x}-{:#x}",
            Self::HIGH_SHADOW_OFFSET,
            Self::HIGH_SHADOW_OFFSET + Self::HIGH_SHADOW_SIZE
        );
        let hi = Self::map_shadow(Self::HIGH_SHADOW_OFFSET, Self::HIGH_SHADOW_SIZE)
            .map_err(|e| GuestShadowError::MmapError(e))?;
        Ok(GuestShadow {
            lo,
            hi,
            _phantom: PhantomData,
        })
    }

    fn map_shadow(addr: GuestAddr, size: usize) -> Result<M, M::Error> {
        let m = M::map_at(addr, size)?;
        M::huge_pages(addr, size)?;
        M::dont_dump(addr, size)?;
        Ok(m)
    }

    pub fn align_down(addr: GuestAddr) -> GuestAddr {
        addr & !(Self::ALLOC_ALIGN_SIZE - 1)
    }

    pub fn align_up(addr: GuestAddr) -> GuestAddr {
        assert!(addr <= GuestAddr::MAX - (Self::ALLOC_ALIGN_SIZE - 1));
        let val = addr + (Self::ALLOC_ALIGN_SIZE - 1);
        val & !(Self::ALLOC_ALIGN_SIZE - 1)
    }

    pub fn remainder(addr: GuestAddr) -> usize {
        addr & (Self::ALLOC_ALIGN_SIZE - 1)
    }

    pub fn is_out_of_bounds(addr: GuestAddr, len: usize) -> bool {
        if len == 0 {
            false
        } else {
            GuestAddr::MAX - len + 1 < addr
        }
    }

    pub fn is_start_aligned(addr: GuestAddr) -> bool {
        let remainder = Self::remainder(addr);
        remainder == 0
    }

    pub fn is_end_aligned(addr: GuestAddr, len: usize) -> bool {
        Self::end_remainder(addr, len) == 0
    }

    pub fn end_remainder(addr: GuestAddr, len: usize) -> usize {
        let start_remainder = Self::remainder(addr);
        let end_remainder = Self::remainder(len);
        Self::remainder(start_remainder + end_remainder)
    }

    pub fn is_memory(addr: GuestAddr, len: usize) -> bool {
        Self::is_low_memory(addr, len) || Self::is_high_memory(addr, len)
    }

    pub fn is_low_memory(addr: GuestAddr, len: usize) -> bool {
        if !(Self::LOW_MEM_OFFSET..=Self::LOW_MEM_LIMIT).contains(&addr) {
            false
        } else {
            len <= Self::LOW_MEM_LIMIT - addr + 1
        }
    }

    pub fn is_high_memory(addr: GuestAddr, len: usize) -> bool {
        if !(Self::HIGH_MEM_OFFSET..=Self::HIGH_MEM_LIMIT).contains(&addr) {
            false
        } else {
            len <= Self::HIGH_MEM_LIMIT - addr + 1
        }
    }

    pub fn get_shadow(&self, addr: GuestAddr, len: usize) -> Result<&[u8], GuestShadowError<M>> {
        trace!("get_shadow - addr: {addr:#x}, len: {len:#x}");
        assert!(addr % Self::ALLOC_ALIGN_SIZE == 0);
        assert!(len % Self::ALLOC_ALIGN_SIZE == 0);
        let shadow_addr = (addr >> Self::ALLOC_ALIGN_POW) + Self::SHADOW_OFFSET;
        let shadow_len = len >> Self::ALLOC_ALIGN_POW;
        if Self::is_low_memory(addr, len) {
            let offset = shadow_addr - Self::LOW_SHADOW_OFFSET;
            Ok(&self.lo.as_slice()[offset..(offset + shadow_len)])
        } else if Self::is_high_memory(addr, len) {
            let offset = shadow_addr - Self::HIGH_SHADOW_OFFSET;
            Ok(&self.hi.as_slice()[offset..(offset + shadow_len)])
        } else {
            Err(GuestShadowError::InvalidMemoryAddress(addr))
        }
    }

    pub fn get_shadow_mut(
        &mut self,
        addr: GuestAddr,
        len: usize,
    ) -> Result<&mut [u8], GuestShadowError<M>> {
        trace!("get_shadow_mut - addr: {addr:#x}, len: {len:#x}");
        assert!(addr % Self::ALLOC_ALIGN_SIZE == 0);
        assert!(len % Self::ALLOC_ALIGN_SIZE == 0);
        let shadow_addr = (addr >> Self::ALLOC_ALIGN_POW) + Self::SHADOW_OFFSET;
        let aligned_len = Self::align_up(len);
        let shadow_len = aligned_len >> Self::ALLOC_ALIGN_POW;
        if Self::is_low_memory(addr, len) {
            let offset = shadow_addr - Self::LOW_SHADOW_OFFSET;
            Ok(&mut self.lo.as_mut_slice()[offset..(offset + shadow_len)])
        } else if Self::is_high_memory(addr, len) {
            let offset = shadow_addr - Self::HIGH_SHADOW_OFFSET;
            Ok(&mut self.hi.as_mut_slice()[offset..(offset + shadow_len)])
        } else {
            Err(GuestShadowError::InvalidMemoryAddress(addr))
        }
    }
}

pub trait ShadowLayout: Debug + Send {
    const LOW_MEM_OFFSET: usize;
    const LOW_MEM_SIZE: usize;

    const LOW_SHADOW_OFFSET: usize;
    const LOW_SHADOW_SIZE: usize;

    const HIGH_SHADOW_OFFSET: usize;
    const HIGH_SHADOW_SIZE: usize;

    const HIGH_MEM_OFFSET: usize;
    const HIGH_MEM_SIZE: usize;

    const SHADOW_OFFSET: usize;
    const ALLOC_ALIGN_POW: usize;
    const ALLOC_ALIGN_SIZE: usize;
}

#[derive(Debug)]
pub struct DefaultShadowLayout;

#[cfg(target_pointer_width = "32")]
impl ShadowLayout for DefaultShadowLayout {
    // [0x40000000, 0xffffffff] 	HighMem
    // [0x28000000, 0x3fffffff] 	HighShadow
    // [0x24000000, 0x27ffffff] 	ShadowGap
    // [0x20000000, 0x23ffffff] 	LowShadow
    // [0x00000000, 0x1fffffff] 	LowMem
    const SHADOW_OFFSET: usize = 0x20000000;
    const LOW_MEM_OFFSET: GuestAddr = 0x0;
    const LOW_MEM_SIZE: usize = 0x20000000;
    const LOW_SHADOW_OFFSET: GuestAddr = 0x20000000;
    const LOW_SHADOW_SIZE: usize = 0x4000000;
    const HIGH_SHADOW_OFFSET: GuestAddr = 0x28000000;
    const HIGH_SHADOW_SIZE: usize = 0x18000000;
    const HIGH_MEM_OFFSET: GuestAddr = 0x40000000;
    const HIGH_MEM_SIZE: usize = 0xc0000000;

    const ALLOC_ALIGN_POW: usize = 3;
    const ALLOC_ALIGN_SIZE: usize = 1 << Self::ALLOC_ALIGN_POW;
}

#[cfg(target_pointer_width = "64")]
impl ShadowLayout for DefaultShadowLayout {
    // [0x10007fff8000, 0x7fffffffffff] 	HighMem
    // [0x02008fff7000, 0x10007fff7fff] 	HighShadow
    // [0x00008fff7000, 0x02008fff6fff] 	ShadowGap
    // [0x00007fff8000, 0x00008fff6fff] 	LowShadow
    // [0x000000000000, 0x00007fff7fff] 	LowMem
    const SHADOW_OFFSET: usize = 0x7fff8000;
    const LOW_MEM_OFFSET: GuestAddr = 0x0;
    const LOW_MEM_SIZE: usize = 0x00007fff8000;
    const LOW_SHADOW_OFFSET: GuestAddr = 0x00007fff8000;
    const LOW_SHADOW_SIZE: usize = 0xffff000;
    const HIGH_SHADOW_OFFSET: GuestAddr = 0x02008fff7000;
    const HIGH_SHADOW_SIZE: usize = 0xdfff0001000;
    const HIGH_MEM_OFFSET: GuestAddr = 0x10007fff8000;
    const HIGH_MEM_SIZE: usize = 0x6fff80008000;

    const ALLOC_ALIGN_POW: usize = 3;
    const ALLOC_ALIGN_SIZE: usize = 1 << Self::ALLOC_ALIGN_POW;
}

#[derive(Error, Debug, PartialEq)]
pub enum GuestShadowError<M: Mmap> {
    #[error("Invalid shadow address: {0:x}")]
    InvalidMemoryAddress(GuestAddr),
    #[error("End address not aligned: {0:x}-{1:x}")]
    UnalignedEndAddress(GuestAddr, usize),
    #[error("Start address not aligned: {0:x}-{1:x}")]
    UnalignedStartAddress(GuestAddr, GuestAddr),
    #[error("Address overflow: {0:x}, len: {1:x}")]
    AddressRangeOverflow(GuestAddr, usize),
    #[error("Poisoned: {0:x}, len: {1:x}")]
    Poisoned(GuestAddr, usize),
    #[error("Mmap error: {0:?}")]
    MmapError(M::Error),
}
