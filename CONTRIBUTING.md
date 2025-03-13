# How to Contribute to LibAFL

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

## Pull Request Guideline

Even though we will gladly assist you in finishing up your PR, try to:

- keep all the crates compiling with *stable* rust (hide the eventual non-stable code under [`cfg`s](https://github.com/AFLplusplus/LibAFL/blob/main/libafl/build.rs#L26))
- run `cargo +nightly fmt` on your code before pushing
- check the output of `cargo clippy --all` or `./scripts/clippy.sh` (On windows use `.\scripts\clippy.ps1`)
- run `cargo build --no-default-features` to check for `no_std` compatibility (and possibly add `#[cfg(feature = "std")]`) to hide parts of your code.
- Please add and describe your changes to MIGRATION.md if you change the APIs.

Some of the parts in this list may be hard, don't be afraid to open a PR if you cannot fix them by yourself, so we can help.

### Pre-commit Hooks

Some of these checks can be performed automatically during commit using [pre-commit](https://pre-commit.com/).
Once the package is installed, simply run `pre-commit install` to enable the hooks, the checks will run automatically before the commit becomes effective.

## LibAFL Code Rules

Before making your pull requests, try to see if your code follows these rules.

- Wherever possible, use `Cow<'static, str>` instead of String.
- `PhantomData` should have the smallest set of types needed. Try not adding `PhantomData` to your struct unless it is really necessary. Also even when you really need `PhantomData`, try to keep the types `T` used in `PhantomData` as smallest as possible 
- Wherever possible, trait implementations with lifetime specifiers should use '_ lifetime elision.
- Complex constructors should be replaced with `typed_builder`, or write code in the builder pattern for yourself.


## Rules for Generics and Associated Types
1. Remove generic restrictions at the definitions (e.g., we do not need to specify that types impl `Serialize`, `Deserialize`, or `Debug` anymore at the struct definitions). Therefore, try avoiding code like this unless the constraint is really necessary.
```rust
pub struct X<A> 
    where
        A: P // <- Do not add contraints here
{
    fn ...
}
```
2. Reduce generics to the least restrictive necessary. __Never overspecify the constraints__. There's no automated tool to check the useless constraints, so you have to verify this manually.
```rust
pub struct X<A> 
    where
        A: P + Q // <- Try to use the as smallest set of constraints as possible. If the code still compiles after deleting Q, then remove it. 
{
    fn ...
}
```

3. Prefer generic to associated types in traits definition as much as possible. They are much easier to use around, and avoid tricky caveats / type repetition in the code. It is also much easier to have unconstrained struct definitions.
Try not to write this:
```rust
pub trait X
{
    type A;
    
    fn a(&self) -> Self::A;
}
```
Try to write this instead:
```rust
pub trait X<A>
{
    fn a(&self) -> A;
}
```

4. Traits which have an associated type (if you have made sure you cannot use a generic instead) should refer to the associated type, not the concrete/generic. In other words, you should only have the associated type when you can define a getter to it. For example, in the following code, you can define a associate type.
```rust
pub trait X 
{
    type A; // <- You should(can) define it as long as you have a getter to it.
    
    fn a(&self) -> Self::A;
}
```
5. Generic naming should be consistent. Do NOT use multiple name for the same generic, it just makes things more confusing. Do:
```rust
pub struct X<A> {
    phantom: PhanomData<A>,
}

impl<A> X<A> {}
```
But not:
```rust
pub struct X<A> {
    phantom: PhanomData<A>,
}

impl<B> X<B> {} // <- Do NOT do that, use A instead of B
```
6. __Ideally__ the types used in the arguments of methods in traits should have the same as the types defined on the traits.
```rust
pub trait X<A, B, C> // <- this trait have 3 generics, A, B, and C
{
    fn do_stuff(&self, a: A, b: B, c: C); // <- this is good because it uses all A, B, and C.
    
    fn do_other_stuff(&self, a: A, b: B); // <- this is not ideal because it does not have C.
}
```
7. Try to avoid cyclical dependency if possible. Sometimes it is necessary but try to avoid it. For example, The following code is a bad example.
```rust
pub struct X {}
pub struct Y {}

pub trait Fuzzer: Sized {
    fn fuzz<EM>(&self, em: &EM) 
    where
        EM: EventManager
    {
        em.do_stuff(self);
    }
}

pub trait EventManager: Sized {
    fn do_stuff<Z>(&self, fuzzer: &Z); // <- This function signature should not take fuzzer
}
```
trait `EventManager` should not implement any method that takes fuzzer, any object that could implement `Fuzzer` trait.


## Formatting
1. Always alphabetically order the type generics. Therefore,
```rust
pub struct X<E, EM, OT, S, Z> {}; // <- Generics are alphabetically ordered
```
But not,
```rust
pub struct X<S, OT, Z, EM, E> {}; // <- Generics are not ordered
```
2. Similarly, generic bounds in `where` clauses should be alphabetically sorted.
Prefer:
```rust
pub trait FooA {}
pub trait FooB {}

pub struct X<A, B>;

impl<A, B> X<A, B>
where
    A: FooA,
    B: FooB,
{}
```
Over:
```rust
pub trait FooA {}
pub trait FooB {}

pub struct X<A, B>;

impl<A, B> X<A, B>
where
    B: FooB, // <-|
             //   | Generic bounds are not alphabetically ordered.
    A: FooA, // <-|
{}
```
