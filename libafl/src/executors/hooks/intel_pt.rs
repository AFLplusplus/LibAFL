use alloc::rc::Rc;
use core::fmt::Debug;
use std::{
    string::{String, ToString},
    vec::Vec,
};

use libafl_intelpt::{error_from_pt_error, Image, IntelPT, SectionCache};
use num_traits::SaturatingAdd;
use serde::Serialize;
use typed_builder::TypedBuilder;

use crate::{corpus::Corpus, executors::hooks::ExecutorHook, state::HasCorpus, Error};

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
#[derive(Debug, TypedBuilder)]
pub struct IntelPTHook<T> {
    #[builder(default = IntelPT::builder().build().unwrap())]
    intel_pt: IntelPT,
    #[builder(setter(transform = |sections: &[Section]| sections_to_image(sections).unwrap()))]
    image: Image,
    map_ptr: *mut T,
    map_len: usize,
}

impl<S, T> ExecutorHook<<S::Corpus as Corpus>::Input, S> for IntelPTHook<T>
where
    S: Serialize + HasCorpus,
    T: SaturatingAdd + From<u8> + Debug,
{
    fn init(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &<S::Corpus as Corpus>::Input) {
        self.intel_pt.enable_tracing().unwrap();
    }

    fn post_exec(&mut self, _state: &mut S, _input: &<S::Corpus as Corpus>::Input) {
        let pt = &mut self.intel_pt;
        pt.disable_tracing().unwrap();

        let _ = pt
            .decode_traces_into_map(&mut self.image, self.map_ptr, self.map_len)
            .inspect_err(|e| log::warn!("Intel PT trace decoding failed: {e}"));
        #[cfg(feature = "intel_pt_export_raw")]
        {
            let _ = pt
                .dump_last_trace_to_file()
                .inspect_err(|e| log::warn!("Intel PT trace save to file failed: {e}"));
        }
    }
}

// It would be nice to have this as a `TryFrom<IntoIter<Section>>`, but Rust's orphan rule doesn't
// like this (and `TryFromIter` is not a thing atm)
fn sections_to_image(sections: &[Section]) -> Result<Image, Error> {
    let mut image_cache = SectionCache::new(Some("image_cache")).map_err(error_from_pt_error)?;
    let mut image = Image::new(Some("image")).map_err(error_from_pt_error)?;

    let mut isids = Vec::with_capacity(sections.len());
    for s in sections {
        let isid = image_cache.add_file(&s.file_path, s.file_offset, s.size, s.virtual_address);
        match isid {
            Err(e) => log::warn!(
                "Error while caching {} {} - skipped",
                s.file_path,
                e.to_string()
            ),
            Ok(id) => isids.push(id),
        }
    }

    let rc_cache = Rc::new(image_cache);
    for isid in isids {
        if let Err(e) = image.add_cached(rc_cache.clone(), isid, None) {
            log::warn!("Error while adding cache to image {}", e.to_string());
        }
    }

    Ok(image)
}
