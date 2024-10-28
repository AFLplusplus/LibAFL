// TODO: docs
#![allow(missing_docs)]

use std::string::String;

use libafl_bolts::intel_pt::IntelPT;
use libipt::{Asid, Image, SectionCache};
use serde::Serialize;
use typed_builder::TypedBuilder;

use crate::{
    executors::{hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
    Error,
};

#[derive(Debug)]
pub struct Section {
    pub file_name: String,
    pub file_offset: usize,
    pub size: usize,
    pub virtual_address: usize,
}

#[derive(Debug, TypedBuilder)]
pub struct IntelPTHook {
    #[builder(default = IntelPT::builder().build().unwrap())]
    intel_pt: IntelPT,
    #[builder(setter(transform = |sections: &[Section]| sections_to_image(sections).unwrap()))]
    image: (Image<'static>, SectionCache<'static>),
    map_ptr: *mut u8,
    map_len: usize,
}

impl<S> ExecutorHook<S> for IntelPTHook
where
    S: UsesInput + Serialize,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}

    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.intel_pt.enable_tracing().unwrap();
    }

    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.intel_pt.disable_tracing().unwrap();

        let decode_res = self.intel_pt.decode_with_image(&mut self.image.0);
        match decode_res {
            Ok(ids) => {
                for ip in ids {
                    unsafe {
                        let map_loc = self.map_ptr.add(ip as usize % self.map_len);
                        *map_loc = (*map_loc).saturating_add(1);
                    }
                }
            }
            Err(e) => log::warn!("Intel PT trace decoding failed: {e}"),
        }
    }
}

fn sections_to_image(
    sections: &[Section],
) -> Result<(Image<'static>, SectionCache<'static>), Error> {
    let mut image_cache = SectionCache::new(Some("image_cache"))?;
    let mut image = Image::new(Some("image"))?;

    for s in sections {
        let isid = image_cache.add_file(
            &s.file_name,
            s.file_offset as u64,
            s.size as u64,
            s.virtual_address as u64,
        )?;
        image.add_cached(&mut image_cache, isid, Asid::default())?;
    }

    Ok((image, image_cache))
}
