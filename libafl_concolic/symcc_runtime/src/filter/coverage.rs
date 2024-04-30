use std::{
    collections::hash_map::DefaultHasher,
    hash::{BuildHasher, BuildHasherDefault, Hash, Hasher},
    marker::PhantomData,
};

use libafl_bolts::shmem::ShMem;

use super::Filter;

const MAP_SIZE: usize = 65536;

/// A coverage-based [`Filter`] based on the
/// [expression pruning](https://github.com/sslab-gatech/qsym/blob/master/qsym/pintool/call_stack_manager.cpp) from
/// [`QSym`](https://github.com/sslab-gatech/qsym).
pub struct CallStackCoverage<
    THasher: Hasher = DefaultHasher,
    THashBuilder: BuildHasher = BuildHasherDefault<THasher>,
> {
    call_stack: Vec<usize>,
    call_stack_hash: u64,
    is_interesting: bool,
    bitmap: Vec<u16>,
    pending: bool,
    last_location: usize,
    hasher_builder: THashBuilder,
    hasher_phantom: PhantomData<THasher>,
}

impl Default for CallStackCoverage<DefaultHasher, BuildHasherDefault<DefaultHasher>> {
    fn default() -> Self {
        Self {
            call_stack: Vec::new(),
            call_stack_hash: 0,
            is_interesting: true,
            bitmap: vec![0; MAP_SIZE],
            pending: false,
            last_location: 0,
            hasher_builder: BuildHasherDefault::default(),
            hasher_phantom: PhantomData,
        }
    }
}

impl<THasher: Hasher, THashBuilder: BuildHasher> CallStackCoverage<THasher, THashBuilder> {
    pub fn visit_call(&mut self, location: usize) {
        self.call_stack.push(location);
        self.update_call_stack_hash();
    }

    pub fn visit_ret(&mut self, location: usize) {
        if self.call_stack.is_empty() {
            return;
        }
        let num_elements_to_remove = self
            .call_stack
            .iter()
            .rev()
            .take_while(|&&loc| loc != location)
            .count()
            + 1;

        self.call_stack
            .truncate(self.call_stack.len() - num_elements_to_remove);
        self.update_call_stack_hash();
    }

    pub fn visit_basic_block(&mut self, location: usize) {
        self.last_location = location;
        self.pending = true;
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn is_interesting(&self) -> bool {
        self.is_interesting
    }

    pub fn update_bitmap(&mut self) {
        if self.pending {
            self.pending = false;

            let mut hasher = self.hasher_builder.build_hasher();
            self.last_location.hash(&mut hasher);
            self.call_stack_hash.hash(&mut hasher);
            let hash = hasher.finish();
            let index: usize = (hash % MAP_SIZE as u64).try_into().unwrap();
            let value = self.bitmap[index] / 8;
            self.is_interesting = value == 0 || value.is_power_of_two();
            *self.bitmap.get_mut(index).unwrap() += 1;
        }
    }

    fn update_call_stack_hash(&mut self) {
        let mut hasher = self.hasher_builder.build_hasher();
        self.call_stack
            .iter()
            .for_each(|&loc| loc.hash(&mut hasher));
        self.call_stack_hash = hasher.finish();
    }
}

macro_rules! call_stack_coverage_filter_function_implementation {
    (pub fn expression_unreachable(expressions: *mut RSymExpr, num_elements: usize), $c_name:ident;) => {
    };

    (pub fn notify_basic_block(site_id: usize), $c_name:ident;) => {
        fn notify_basic_block(&mut self, site_id: usize) {
            self.visit_basic_block(site_id);
        }
    };
    (pub fn notify_call(site_id: usize), $c_name:ident;) => {
        fn notify_call(&mut self, site_id: usize) {
            self.visit_call(site_id);
        }
    };
    (pub fn notify_ret(site_id: usize), $c_name:ident;) => {
        fn notify_ret(&mut self, site_id: usize) {
            self.visit_ret(site_id);
        }
    };

    (pub fn push_path_constraint($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        fn push_path_constraint(&mut self, $( _ : $type ),*) -> bool {
            self.update_bitmap();
            self.is_interesting()
        }
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?) -> $ret:ty, $c_name:ident;) => {
        fn $name(&mut self, $( _ : $type),*) -> bool {
            self.update_bitmap();
            self.is_interesting()
        }
    };

    (pub fn $name:ident($( $arg:ident : $type:ty ),*$(,)?), $c_name:ident;) => {
        fn $name(&mut self, $( _ : $type),*) {
        }
    };
}

#[allow(clippy::wildcard_imports)]
use crate::*;

impl<THasher: Hasher, THashBuilder: BuildHasher> Filter
    for CallStackCoverage<THasher, THashBuilder>
{
    invoke_macro_with_rust_runtime_exports!(call_stack_coverage_filter_function_implementation;);
}

/// A [`Filter`] that just observes Basic Block locations and updates a given Hitmap as a [`ShMem`].
pub struct HitmapFilter<M, BH: BuildHasher = BuildHasherDefault<DefaultHasher>> {
    hitcounts_map: M,
    build_hasher: BH,
}

impl<M> HitmapFilter<M, BuildHasherDefault<DefaultHasher>>
where
    M: ShMem,
{
    /// Creates a new `HitmapFilter` using the given map and the [`DefaultHasher`].
    pub fn new(hitcounts_map: M) -> Self {
        Self::with_default_hasher_builder(hitcounts_map)
    }
}

impl<M, H> HitmapFilter<M, BuildHasherDefault<H>>
where
    M: ShMem,
    H: Hasher + Default,
{
    /// Creates a new `HitmapFilter` using the given map and [`Hasher`] (as type argument) using the [`BuildHasherDefault`].
    pub fn with_default_hasher_builder(hitcounts_map: M) -> Self {
        Self::with_build_hasher(hitcounts_map, BuildHasherDefault::default())
    }
}

impl<M, BH> HitmapFilter<M, BH>
where
    M: ShMem,
    BH: BuildHasher,
{
    /// Creates a new `HitmapFilter` using the given map and [`BuildHasher`] (as type argument).
    pub fn with_build_hasher(hitcounts_map: M, build_hasher: BH) -> Self {
        Self {
            hitcounts_map,
            build_hasher,
        }
    }

    fn register_location_on_hitmap(&mut self, location: usize) {
        #[allow(clippy::cast_possible_truncation)] // we cannot have more than usize elements..
        let hash = (self.build_hasher.hash_one(location) % usize::MAX as u64) as usize;
        let val = unsafe {
            // # Safety
            // The index is modulo by the length, therefore it is always in bounds
            let len = self.hitcounts_map.len();
            self.hitcounts_map.get_unchecked_mut(hash % len)
        };
        *val = val.saturating_add(1);
    }
}

impl<M, BH> Filter for HitmapFilter<M, BH>
where
    M: ShMem,
    BH: BuildHasher,
{
    fn notify_basic_block(&mut self, location_id: usize) {
        self.register_location_on_hitmap(location_id);
    }
}
