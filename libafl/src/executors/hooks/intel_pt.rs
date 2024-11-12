use core::fmt::Debug;
use std::{
    ptr::slice_from_raw_parts_mut,
    string::{String, ToString},
};

use libafl_intelpt::{error_from_pt_error, IntelPT};
use libipt::{Asid, Image, SectionCache};
use num_traits::SaturatingAdd;
use serde::Serialize;
use typed_builder::TypedBuilder;

use crate::{
    executors::{hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
    Error,
};

/// Info of a binary's section that can be used during `Intel PT` traces decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Path of the binary
    pub file_path: String,
    /// Offset of the section in the file
    pub file_offset: u64,
    /// Size of the section
    pub size: u64,
    /// Start virtual address of the section once loaded in memory
    pub virtual_address: u64,
}

/// Hook to enable Intel Processor Trace (PT) tracing
#[derive(TypedBuilder)]
pub struct IntelPTHook<T> {
    #[builder(default = IntelPT::builder().build().unwrap())]
    intel_pt: IntelPT,
    #[builder(setter(transform = |sections: &[Section]| sections_to_image(sections).unwrap()))]
    image: (Image<'static>, SectionCache<'static>),
    map_ptr: *mut T,
    map_len: usize,
}

//fixme: just derive(Debug) once https://github.com/sum-catnip/libipt-rs/pull/4 will be on crates.io
impl<T> Debug for IntelPTHook<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("IntelPTHook")
            .field("intel_pt", &self.intel_pt)
            .field("map_ptr", &self.map_ptr)
            .field("map_len", &self.map_len)
            .finish()
    }
}

impl<S, T> ExecutorHook<S> for IntelPTHook<T>
where
    S: UsesInput + Serialize,
    T: SaturatingAdd + From<u8> + Debug,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.intel_pt.enable_tracing().unwrap();
    }

    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.intel_pt.disable_tracing().unwrap();

        let slice = unsafe { &mut *slice_from_raw_parts_mut(self.map_ptr, self.map_len) };
        let _ = self
            .intel_pt
            .decode_traces_into_map(&mut self.image.0, slice)
            .inspect_err(|e| log::warn!("Intel PT trace decoding failed: {e}"));
    }
}

// It would be nice to have this as a `TryFrom<IntoIter<Section>>`, but Rust's orphan rule doesn't
// like this (and `TryFromIter` is not a thing atm)
fn sections_to_image(
    sections: &[Section],
) -> Result<(Image<'static>, SectionCache<'static>), Error> {
    let mut image_cache = SectionCache::new(Some("image_cache")).map_err(error_from_pt_error)?;
    let mut image = Image::new(Some("image")).map_err(error_from_pt_error)?;

    for s in sections {
        let isid = image_cache.add_file(&s.file_path, s.file_offset, s.size, s.virtual_address);
        if let Err(e) = isid {
            log::warn!(
                "Error while caching {} {} - skipped",
                s.file_path,
                e.to_string()
            );
            continue;
        }

        if let Err(e) = image.add_cached(&mut image_cache, isid.unwrap(), Asid::default()) {
            log::warn!(
                "Error while adding cache to image {} {} - skipped",
                s.file_path,
                e.to_string()
            );
            continue;
        }
    }

    Ok((image, image_cache))
}
