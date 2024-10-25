// TODO: docs
#![allow(missing_docs)]

use std::{ops::RangeInclusive, process};

use libafl_bolts::intel_pt::IntelPT;
use libipt::{Asid, Image, SectionCache};
use proc_maps::get_process_maps;
use serde::Serialize;

use crate::{
    executors::{command::SerdeAnyi32, hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
    state::HasCorpus,
    HasNamedMetadata,
};

#[derive(Debug)]
pub struct IntelPTHook {
    pt: Option<IntelPT>,
    image: Option<Image<'static>>,
    image_cache: Option<SectionCache<'static>>,
    map: *mut u8,
    len: usize,
}
use std::vec::Vec;

#[derive(Debug)]
pub struct IntelPTChildHook {
    pt: Option<IntelPT>,
    image: Option<Image<'static>>,
    image_cache: Option<SectionCache<'static>>,
    ip_filters: Vec<RangeInclusive<usize>>,
    map: *mut u8,
    len: usize,
}

impl IntelPTChildHook {
    pub fn new(map: *mut u8, len: usize, ip_filters: &[RangeInclusive<usize>]) -> Self {
        Self {
            pt: None,
            image: None,
            image_cache: None,
            ip_filters: ip_filters.to_vec(),
            map,
            len,
        }
    }
}

// TODO remove some S traits
impl<S> ExecutorHook<S> for IntelPTChildHook
where
    S: UsesInput + Serialize + HasNamedMetadata + HasCorpus,
    S::Corpus: core::fmt::Debug,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {
        assert!(self.image.is_none(), "Intel PT image was already set up");
        assert!(
            self.image_cache.is_none(),
            "Intel PT cache was already set up"
        );
        let mut image_cache = SectionCache::new(Some("image_cache")).unwrap();
        let mut image = Image::new(Some("image")).unwrap();
        let pid: SerdeAnyi32 = *_state
            .named_metadata_map()
            .get("child")
            .expect("Child pid not in state metadata");

        let maps = get_process_maps(pid.inner).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                if let Ok(isid) = image_cache.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    map.start() as u64,
                ) {
                    image
                        .add_cached(&mut image_cache, isid, Asid::default())
                        .unwrap();
                    log::info!(
                        "mapped {}\toffset: {:x}\tsize: {:x}\t start: {:x}",
                        map.filename().unwrap().to_str().unwrap(),
                        map.offset as u64,
                        map.size() as u64,
                        map.start() as u64,
                    );
                }
            }
        }

        self.image_cache = Some(image_cache);
        self.image = Some(image);

        assert!(self.pt.is_none(), "Intel PT was already set up");

        let pt_builder = IntelPT::builder().cpu(Some(0)).inherit(true); //.pid(Some(pid.inner))
        self.pt = Some(pt_builder.build().unwrap());
        self.pt
            .as_mut()
            .unwrap()
            .set_ip_filters(&self.ip_filters)
            .unwrap();
    }

    #[allow(clippy::cast_possible_wrap)]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.pt.as_mut().unwrap().enable_tracing().unwrap();
    }

    #[allow(clippy::cast_possible_wrap)]
    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        let pt = self.pt.as_mut().unwrap();
        pt.disable_tracing().unwrap();

        let decode_res = pt.decode_with_image(self.image.as_mut().unwrap());

        match decode_res {
            Ok(ids) => {
                for ip in ids {
                    unsafe {
                        let map_loc = self.map.add(ip as usize % self.len);
                        *map_loc = (*map_loc).saturating_add(1);
                    }
                }
            }
            Err(e) => log::warn!("Intel PT trace decoding failed: {e}"),
        }

        // println!("{:?}", _state.corpus());

        // self.pt = None;
    }
}

impl IntelPTHook {
    pub fn new(map: *mut u8, len: usize) -> Self {
        Self {
            pt: None,
            image: None,
            image_cache: None,
            map,
            len,
        }
    }
}
impl<S> ExecutorHook<S> for IntelPTHook
where
    S: UsesInput + Serialize,
{
    #[allow(clippy::cast_possible_wrap)]
    fn init<E: HasObservers>(&mut self, _state: &mut S) {
        assert!(self.pt.is_none(), "Intel PT was already set up");
        assert!(self.image.is_none(), "Intel PT image was already set up");
        assert!(
            self.image_cache.is_none(),
            "Intel PT cache was already set up"
        );

        let mut image_cache = SectionCache::new(Some("image_cache")).unwrap();
        let mut image = Image::new(Some("image")).unwrap();

        let pid = process::id();
        let maps = get_process_maps(pid as i32).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                if let Ok(isid) = image_cache.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    map.start() as u64,
                ) {
                    image
                        .add_cached(&mut image_cache, isid, Asid::default())
                        .unwrap();
                }
            }
        }

        self.image_cache = Some(image_cache);
        self.image = Some(image);
        let pt_builder = IntelPT::builder();
        self.pt = Some(pt_builder.build().unwrap());
    }

    #[allow(clippy::cast_possible_wrap)]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.pt.as_mut().unwrap().enable_tracing().unwrap();
    }

    #[allow(clippy::cast_possible_wrap)]
    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        let pt = self.pt.as_mut().unwrap();
        pt.disable_tracing().unwrap();

        // let read_mem = |buf: &mut [u8], addr: u64| {
        //     let src = addr as *const u8;
        //     let dst = buf.as_mut_ptr();
        //     let size = buf.len();
        //     unsafe {
        //         ptr::copy_nonoverlapping(src, dst, size);
        //     }
        // };

        let decode_res = pt.decode_with_image(self.image.as_mut().unwrap());

        if let Ok(ids) = decode_res {
            for ip in ids {
                unsafe {
                    let map_loc = self.map.add(ip as usize % self.len);
                    *map_loc = (*map_loc).saturating_add(1);
                };
            }
        }
    }
}
