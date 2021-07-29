use std::collections::HashSet;

use concolic::SymExpr;

/// An [`ExpressionFilter`] can decide for each expression whether the expression should be trace symbolically or be
/// concretized. This allows to implement filtering mechanisms that reduce the amount of traced expressions by
/// concretizing uninteresting expressions.
/// If an expression filter concretizes an expression that would have later been used as part of another expression that
/// is still symbolic, a concrete instead of a symbolic value is received.
///
/// For example:
/// Suppose there are symbolic expressions `a` and `b`. Expression `a` is concretized, `b` is still symbolic. If an add
/// operation between `a` and `b` is encountered, it will receive `a`'s concrete value and `b` as a symbolic expression.
///
/// An expression filter also receives code locations (`notifiy_*` methods) as they are visited in between operations
/// and these code locations are typically used to decide whether an expression should be concretized.
pub trait ExpressionFilter {
    /// Decides whether the expression should continue to be symbolic. If this method returns `true` the expression will
    /// continue to be symbolic, else the value will be concretized in future expressions.
    fn symbolize(&mut self, msg: &SymExpr) -> bool;

    /// This function is called on function entry and receives a location id.
    ///
    /// Note that this location id is _not_ the location of the function in memory, but rather a random identifier.
    /// Location ids are equal for equal locations in the program, but carry no other meaning.
    fn notify_call(&mut self, location_id: usize);

    /// This function is called on function exit and receives a location id.
    ///
    /// Note that this location id is _not_ the location of the function in memory, but rather a random identifier.
    /// Location ids are equal for equal locations in the program, but carry no other meaning.
    fn notify_return(&mut self, location_id: usize);

    /// This function is called on basic block entry and receives a location id.
    ///
    /// Note that this location id is _not_ the location of the function in memory, but rather a random identifier.
    /// Location ids are equal for equal locations in the program, but carry no other meaning.
    fn notify_basic_block(&mut self, location_id: usize);
}

/// An expression filter that always keeps expressions symbolic.
pub struct Nop;

impl ExpressionFilter for Nop {
    fn symbolize(&mut self, _msg: &SymExpr) -> bool {
        true
    }
    fn notify_call(&mut self, _location_id: usize) {}
    fn notify_return(&mut self, _location_id: usize) {}
    fn notify_basic_block(&mut self, _location_id: usize) {}
}

/// An [`ExpressionFilter`] that concretizes all input byte expressions that are not included in a predetermined set of
/// of input byte offsets.
pub struct SelectiveSymbolication {
    bytes_to_symbolize: HashSet<usize>,
}

impl SelectiveSymbolication {
    pub(crate) fn new(offset: HashSet<usize>) -> Self {
        Self {
            bytes_to_symbolize: offset,
        }
    }
}

impl ExpressionFilter for SelectiveSymbolication {
    fn symbolize(&mut self, msg: &SymExpr) -> bool {
        if let SymExpr::GetInputByte { offset } = msg {
            self.bytes_to_symbolize.contains(offset)
        } else {
            true
        }
    }
    fn notify_call(&mut self, _location_id: usize) {}
    fn notify_return(&mut self, _location_id: usize) {}
    fn notify_basic_block(&mut self, _location_id: usize) {}
}

/// An [`ExpressionFilter`] that combines two expression filters and decides to symbolize expressions where both filters
/// decide to symbolize.
pub struct And<A: ExpressionFilter, B: ExpressionFilter> {
    a: A,
    b: B,
}

impl<A: ExpressionFilter, B: ExpressionFilter> ExpressionFilter for And<A, B> {
    fn symbolize(&mut self, msg: &SymExpr) -> bool {
        self.a.symbolize(msg) && self.b.symbolize(msg)
    }
    fn notify_call(&mut self, location_id: usize) {
        self.a.notify_call(location_id);
        self.b.notify_call(location_id);
    }
    fn notify_return(&mut self, location_id: usize) {
        self.a.notify_return(location_id);
        self.b.notify_return(location_id);
    }
    fn notify_basic_block(&mut self, location_id: usize) {
        self.a.notify_basic_block(location_id);
        self.b.notify_basic_block(location_id);
    }
}

pub struct AndOpt<A: ExpressionFilter, B: ExpressionFilter> {
    a: A,
    b: Option<B>,
}

impl<A: ExpressionFilter, B: ExpressionFilter> ExpressionFilter for AndOpt<A, B> {
    fn symbolize(&mut self, msg: &SymExpr) -> bool {
        self.a.symbolize(msg) && self.b.as_mut().map_or(true, |b| b.symbolize(msg))
    }
    fn notify_call(&mut self, location_id: usize) {
        self.a.notify_call(location_id);
        if let Some(b) = self.b.as_mut() {
            b.notify_call(location_id)
        }
    }
    fn notify_return(&mut self, location_id: usize) {
        self.a.notify_return(location_id);
        if let Some(b) = self.b.as_mut() {
            b.notify_return(location_id)
        }
    }
    fn notify_basic_block(&mut self, location_id: usize) {
        self.a.notify_basic_block(location_id);
        if let Some(b) = self.b.as_mut() {
            b.notify_basic_block(location_id)
        }
    }
}

pub trait ExpressionFilterExt: ExpressionFilter {
    /// Combines two filters into a new filter that decides to symbolize if _both_ this filter and the given filter
    /// decide to symbolize.
    fn and<Other: ExpressionFilter>(self, other: Other) -> And<Self, Other>
    where
        Self: Sized;

    /// Combines two filters into a new filter that decides to symbolize if _both_ this filter and the given filter
    /// decide to symbolize. Accepts an optional for the combined filter and ignores it if set to None.
    fn and_optionally<Other: ExpressionFilter>(self, other: Option<Other>) -> AndOpt<Self, Other>
    where
        Self: Sized;
}

impl<F: ExpressionFilter> ExpressionFilterExt for F {
    fn and<Other: ExpressionFilter>(self, other: Other) -> And<Self, Other>
    where
        Self: Sized,
    {
        And { a: self, b: other }
    }

    fn and_optionally<Other: ExpressionFilter>(self, other: Option<Other>) -> AndOpt<Self, Other>
    where
        Self: Sized,
    {
        AndOpt { a: self, b: other }
    }
}

/// Concretizes all floating point operations.
pub struct NoFloat;

impl ExpressionFilter for NoFloat {
    fn symbolize(&mut self, msg: &SymExpr) -> bool {
        !matches!(
            msg,
            SymExpr::BuildFloat { .. }
                | SymExpr::BuildFloatOrdered { .. }
                | SymExpr::BuildFloatOrderedGreaterThan { .. }
                | SymExpr::BuildFloatOrderedGreaterEqual { .. }
                | SymExpr::BuildFloatOrderedLessThan { .. }
                | SymExpr::BuildFloatOrderedLessEqual { .. }
                | SymExpr::BuildFloatOrderedEqual { .. }
                | SymExpr::BuildFloatOrderedNotEqual { .. }
                | SymExpr::BuildFloatUnordered { .. }
                | SymExpr::BuildFloatUnorderedGreaterThan { .. }
                | SymExpr::BuildFloatUnorderedGreaterEqual { .. }
                | SymExpr::BuildFloatUnorderedLessThan { .. }
                | SymExpr::BuildFloatUnorderedLessEqual { .. }
                | SymExpr::BuildFloatUnorderedEqual { .. }
                | SymExpr::BuildFloatUnorderedNotEqual { .. }
                | SymExpr::BuildFloatAbs { .. }
                | SymExpr::BuildFloatAdd { .. }
                | SymExpr::BuildFloatSub { .. }
                | SymExpr::BuildFloatMul { .. }
                | SymExpr::BuildFloatDiv { .. }
                | SymExpr::BuildFloatRem { .. }
                | SymExpr::BuildIntToFloat { .. }
                | SymExpr::BuildFloatToFloat { .. }
                | SymExpr::BuildBitsToFloat { .. }
                | SymExpr::BuildFloatToBits { .. }
                | SymExpr::BuildFloatToSignedInteger { .. }
                | SymExpr::BuildFloatToUnsignedInteger { .. }
        )
    }

    fn notify_call(&mut self, _location_id: usize) {}

    fn notify_return(&mut self, _location_id: usize) {}

    fn notify_basic_block(&mut self, _location_id: usize) {}
}

pub mod coverage {
    use std::{
        collections::hash_map::DefaultHasher,
        convert::TryInto,
        hash::{BuildHasher, BuildHasherDefault, Hash, Hasher},
        marker::PhantomData,
    };

    use libafl::bolts::shmem::ShMem;

    use super::ExpressionFilter;

    const MAP_SIZE: usize = 65536;

    /// A coverage-based filter based on the expression pruning from [`QSym`](https://github.com/sslab-gatech/qsym)
    /// [here](https://github.com/sslab-gatech/qsym/blob/master/qsym/pintool/call_stack_manager.cpp).
    pub(crate) struct CallStackCoverage<
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
            self.update_call_stack_hash()
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

    impl ExpressionFilter for CallStackCoverage {
        fn symbolize(&mut self, _msg: &concolic::SymExpr) -> bool {
            self.update_bitmap();
            self.is_interesting()
        }

        fn notify_call(&mut self, location_id: usize) {
            self.visit_call(location_id)
        }

        fn notify_return(&mut self, location_id: usize) {
            self.visit_ret(location_id)
        }

        fn notify_basic_block(&mut self, location_id: usize) {
            self.visit_basic_block(location_id)
        }
    }

    /// An expression filter that just observers Basic Block locations and updates a given Hitmap as a [`ShMem`].
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
            Self::new_with_default_hasher_builder(hitcounts_map)
        }
    }

    impl<M, H> HitmapFilter<M, BuildHasherDefault<H>>
    where
        M: ShMem,
        H: Hasher + Default,
    {
        /// Creates a new `HitmapFilter` using the given map and [`Hasher`] (as type argument) using the [`BuildHasherDefault`].
        pub fn new_with_default_hasher_builder(hitcounts_map: M) -> Self {
            Self::new_with_build_hasher(hitcounts_map, BuildHasherDefault::default())
        }
    }

    impl<M, BH> HitmapFilter<M, BH>
    where
        M: ShMem,
        BH: BuildHasher,
    {
        /// Creates a new `HitmapFilter` using the given map and [`BuildHasher`] (as type argument).
        pub fn new_with_build_hasher(hitcounts_map: M, build_hasher: BH) -> Self {
            Self {
                hitcounts_map,
                build_hasher,
            }
        }

        fn register_location_on_hitmap(&mut self, location: usize) {
            let mut hasher = self.build_hasher.build_hasher();
            location.hash(&mut hasher);
            let hash = hasher.finish() as usize;
            let val = unsafe {
                // SAFETY: the index is modulo by the length, therefore it is always in bounds
                let len = self.hitcounts_map.len();
                self.hitcounts_map.map_mut().get_unchecked_mut(hash % len)
            };
            *val = val.saturating_add(1);
        }
    }

    impl<M, BH> ExpressionFilter for HitmapFilter<M, BH>
    where
        M: ShMem,
        BH: BuildHasher,
    {
        fn symbolize(&mut self, _msg: &concolic::SymExpr) -> bool {
            true
        }

        fn notify_call(&mut self, _location_id: usize) {}

        fn notify_return(&mut self, _location_id: usize) {}

        fn notify_basic_block(&mut self, location_id: usize) {
            self.register_location_on_hitmap(location_id)
        }
    }
}
