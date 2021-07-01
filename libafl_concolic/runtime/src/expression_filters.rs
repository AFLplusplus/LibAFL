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
pub(crate) trait ExpressionFilter {
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
pub(crate) struct NopExpressionFilter;

impl ExpressionFilter for NopExpressionFilter {
    fn symbolize(&mut self, _msg: &SymExpr) -> bool {
        true
    }
    fn notify_call(&mut self, _location_id: usize) {}
    fn notify_return(&mut self, _location_id: usize) {}
    fn notify_basic_block(&mut self, _location_id: usize) {}
}

/// An [`ExpressionFilter`] that concretizes all input byte expressions that are not included in a predetermined set of
/// of input byte offsets.
pub(crate) struct SelectiveSymbolicationFilter {
    bytes_to_symbolize: HashSet<usize>,
}

impl SelectiveSymbolicationFilter {
    pub(crate) fn from_offsets(offset: HashSet<usize>) -> Self {
        Self {
            bytes_to_symbolize: offset,
        }
    }
}

impl ExpressionFilter for SelectiveSymbolicationFilter {
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

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub(crate) const SELECTIVE_SYMBOLICATION_ENV_NAME: &'static str = "LIBAFL_SELECTIVE_SYMBOLICATION";

/// An [`ExpressionFilter`] that combines two expression filters and decides to symbolize expressions where both filters
/// decide to symbolize.
pub(crate) struct AndExpressionFilter<A: ExpressionFilter, B: ExpressionFilter> {
    a: A,
    b: B,
}

impl<A: ExpressionFilter, B: ExpressionFilter> ExpressionFilter for AndExpressionFilter<A, B> {
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

pub(crate) trait ExpressionFilterExt: ExpressionFilter {
    /// Combines two filters into a new filter that decides to symbolize if _both_ this filter and the given filter
    /// decide to symbolize.
    fn and<Other: ExpressionFilter>(self, other: Other) -> AndExpressionFilter<Self, Other>
    where
        Self: Sized;
}

impl<F: ExpressionFilter> ExpressionFilterExt for F {
    fn and<Other: ExpressionFilter>(self, other: Other) -> AndExpressionFilter<Self, Other>
    where
        Self: Sized,
    {
        AndExpressionFilter { a: self, b: other }
    }
}
