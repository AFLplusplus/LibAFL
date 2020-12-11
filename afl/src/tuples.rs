pub use tuple_list::tuple_list;
pub use tuple_list::tuple_list_type;
pub use tuple_list::TupleList;

use core::any::TypeId;

pub trait HasLen {
    fn len(&self) -> usize;
}

impl HasLen for () {
    fn len(&self) -> usize {
        0
    }
}

impl<Head, Tail> HasLen for (Head, Tail)
where
    Tail: TupleList + HasLen,
{
    fn len(&self) -> usize {
        1 + self.1.len()
    }
}

pub trait MatchFirstType {
    fn match_first_type<T: 'static>(&self) -> Option<&T>;
    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T>;
}

impl MatchFirstType for () {
    fn match_first_type<T: 'static>(&self) -> Option<&T> {
        None
    }
    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchFirstType for (Head, Tail)
where
    Head: 'static,
    Tail: TupleList + MatchFirstType,
{
    fn match_first_type<T: 'static>(&self) -> Option<&T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            unsafe { (&self.0 as *const _ as *const T).as_ref() }
        } else {
            self.1.match_first_type::<T>()
        }
    }

    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }
        } else {
            self.1.match_first_type_mut::<T>()
        }
    }
}

pub trait MatchType {
    fn match_type<T: 'static>(&self, f: fn(t: &T));
    fn match_type_mut<T: 'static>(&mut self, f: fn(t: &mut T));
}

impl MatchType for () {
    fn match_type<T: 'static>(&self, f: fn(t: &T)) {
        ()
    }
    fn match_type_mut<T: 'static>(&mut self, f: fn(t: &mut T)) {
        ()
    }
}

impl<Head, Tail> MatchType for (Head, Tail)
where
    Head: 'static,
    Tail: TupleList + MatchType,
{
    fn match_type<T: 'static>(&self, f: fn(t: &T)) {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (&self.0 as *const _ as *const T).as_ref() }.unwrap());
        }
        self.1.match_type::<T>(f);
    }

    fn match_type_mut<T: 'static>(&mut self, f: fn(t: &mut T)) {
        if TypeId::of::<T>() == TypeId::of::<Head>() {
            f(unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }.unwrap());
        }
        self.1.match_type_mut::<T>(f);
    }
}

pub trait Named {
    fn name(&self) -> &str;
}

pub trait MatchNameAndType {
    fn match_name_type<T: 'static>(&self, name: &'static str) -> Option<&T>;
    fn match_name_type_mut<T: 'static>(&mut self, name: &'static str) -> Option<&mut T>;
}

impl MatchNameAndType for () {
    fn match_name_type<T: 'static>(&self, name: &'static str) -> Option<&T> {
        None
    }
    fn match_name_type_mut<T: 'static>(&mut self, name: &'static str) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchNameAndType for (Head, Tail)
where
    Head: 'static + Named,
    Tail: TupleList + MatchNameAndType,
{
    fn match_name_type<T: 'static>(&self, name: &'static str) -> Option<&T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() && name == self.0.name() {
            unsafe { (&self.0 as *const _ as *const T).as_ref() }
        } else {
            self.1.match_name_type::<T>(name)
        }
    }

    fn match_name_type_mut<T: 'static>(&mut self, name: &'static str) -> Option<&mut T> {
        if TypeId::of::<T>() == TypeId::of::<Head>() && name == self.0.name() {
            unsafe { (&mut self.0 as *mut _ as *mut T).as_mut() }
        } else {
            self.1.match_name_type_mut::<T>(name)
        }
    }
}

pub trait Prepend<T>: TupleList {
    type PreprendResult: TupleList;

    fn prepend(self, value: T) -> (T, Self::PreprendResult);
}

/// Implement prepend for tuple list.
impl<Tail, T> Prepend<T> for Tail
where
    Tail: TupleList,
{
    type PreprendResult = Self;

    fn prepend(self, value: T) -> (T, Self::PreprendResult) {
        (value, self)
    }
}

pub trait Append<T>: TupleList {
    type AppendResult: TupleList;

    fn append(self, value: T) -> Self::AppendResult;
}

/// Implement append for an empty tuple list.
impl<T> Append<T> for () {
    type AppendResult = (T, ());

    fn append(self, value: T) -> Self::AppendResult {
        (value, ())
    }
}

/// Implement append for non-empty tuple list.
impl<Head, Tail, T> Append<T> for (Head, Tail)
where
    Self: TupleList,
    Tail: Append<T>,
    (Head, Tail::AppendResult): TupleList,
{
    type AppendResult = (Head, Tail::AppendResult);

    fn append(self, value: T) -> Self::AppendResult {
        let (head, tail) = self;
        return (head, tail.append(value));
    }
}

/*

// Define trait and implement it for several primitive types.
trait PlusOne {
    fn plus_one(&mut self);
}
impl PlusOne for i32    { fn plus_one(&mut self) { *self += 1; } }
impl PlusOne for String { fn plus_one(&mut self) { self.push('1'); } }

// Now we have to implement trait for an empty tuple,
// thus defining initial condition.
impl PlusOne for () {
    fn plus_one(&mut self) {}
}

// Now we can implement trait for a non-empty tuple list,
// thus defining recursion and supporting tuple lists of arbitrary length.
impl<Head, Tail> PlusOne for (Head, Tail) where
    Head: PlusOne,
    Tail: PlusOne + TupleList,
{
    fn plus_one(&mut self) {
        self.0.plus_one();
        self.1.plus_one();
    }
}

*/
