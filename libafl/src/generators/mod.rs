//! Generators may generate bytes or, in general, data, for inputs.

use alloc::vec::Vec;
use core::marker::PhantomData;

use libafl_bolts::rands::Rand;

use crate::{
    inputs::{bytes::BytesInput, Input},
    state::HasRand,
    Error,
};

pub mod gramatron;
pub use gramatron::*;

#[cfg(feature = "nautilus")]
pub mod nautilus;
#[cfg(feature = "nautilus")]
pub use nautilus::*;

/// Generators can generate ranges of bytes.
pub trait Generator<I, S>
where
    I: Input,
{
    /// Generate a new input
    fn generate(&mut self, state: &mut S) -> Result<I, Error>;
}

/// Iterators may be used as generators.
///
/// `generate` throws a [`Error::Empty`] if an input is requested but
/// [`Iterator::next`] returns `None`.
impl<T, I, S> Generator<I, S> for T
where
    T: Iterator<Item = I>,
    I: Input,
{
    fn generate(&mut self, _state: &mut S) -> Result<I, Error> {
        match self.next() {
            Some(i) => Ok(i),
            None => Err(Error::empty(
                "No more items in iterator when generating inputs",
            )),
        }
    }
}

/// An [`Iterator`] built from a [`Generator`].
#[derive(Debug)]
pub struct GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    gen: G,
    state: &'a mut S,
    phantom: PhantomData<I>,
}

impl<'a, I, S, G> GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    /// Create a new [`GeneratorIter`]
    pub fn new(gen: G, state: &'a mut S) -> Self {
        Self {
            gen,
            state,
            phantom: PhantomData,
        }
    }
}

impl<'a, I, S, G> Iterator for GeneratorIter<'a, I, S, G>
where
    I: Input,
    G: Generator<I, S>,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        self.gen.generate(self.state).ok()
    }
}

#[derive(Clone, Debug)]
/// Generates random bytes
pub struct RandBytesGenerator<S>
where
    S: HasRand,
{
    max_size: usize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandBytesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| state.rand_mut().below(256) as u8)
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandBytesGenerator<S>
where
    S: HasRand,
{
    /// Returns a new [`RandBytesGenerator`], generating up to `max_size` random bytes.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
/// Generates random printable characters
pub struct RandPrintablesGenerator<S>
where
    S: HasRand,
{
    max_size: usize,
    phantom: PhantomData<S>,
}

impl<S> Generator<BytesInput, S> for RandPrintablesGenerator<S>
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<BytesInput, Error> {
        let mut size = state.rand_mut().below(self.max_size as u64);
        if size == 0 {
            size = 1;
        }
        let printables = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let random_bytes: Vec<u8> = (0..size)
            .map(|_| *state.rand_mut().choose(printables))
            .collect();
        Ok(BytesInput::new(random_bytes))
    }
}

impl<S> RandPrintablesGenerator<S>
where
    S: HasRand,
{
    /// Creates a new [`RandPrintablesGenerator`], generating up to `max_size` random printable characters.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            phantom: PhantomData,
        }
    }
}

/// `Generator` Python bindings
#[allow(missing_docs)]
#[cfg(feature = "python")]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
pub mod pybind {
    use alloc::vec::Vec;

    use pyo3::prelude::*;

    use crate::{
        generators::{Generator, RandBytesGenerator, RandPrintablesGenerator},
        inputs::{BytesInput, HasBytesVec},
        state::pybind::{PythonStdState, PythonStdStateWrapper},
        Error,
    };

    #[derive(Clone, Debug)]
    pub struct PyObjectGenerator {
        inner: PyObject,
    }

    impl PyObjectGenerator {
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            PyObjectGenerator { inner: obj }
        }
    }

    impl Generator<BytesInput, PythonStdState> for PyObjectGenerator {
        fn generate(&mut self, state: &mut PythonStdState) -> Result<BytesInput, Error> {
            let bytes = Python::with_gil(|py| -> PyResult<Vec<u8>> {
                self.inner
                    .call_method1(py, "generate", (PythonStdStateWrapper::wrap(state),))?
                    .extract(py)
            })
            .unwrap();
            Ok(BytesInput::new(bytes))
        }
    }

    #[pyclass(unsendable, name = "RandBytesGenerator")]
    #[derive(Debug, Clone)]
    /// Python class for RandBytesGenerator
    pub struct PythonRandBytesGenerator {
        /// Rust wrapped RandBytesGenerator object
        pub inner: RandBytesGenerator<PythonStdState>,
    }

    #[pymethods]
    impl PythonRandBytesGenerator {
        #[new]
        fn new(max_size: usize) -> Self {
            Self {
                inner: RandBytesGenerator::new(max_size),
            }
        }

        fn generate(&mut self, state: &mut PythonStdStateWrapper) -> Vec<u8> {
            self.inner
                .generate(state.unwrap_mut())
                .expect("PythonRandBytesGenerator::generate failed")
                .bytes()
                .to_vec()
        }

        fn as_generator(slf: Py<Self>) -> PythonGenerator {
            PythonGenerator::new_rand_bytes(slf)
        }
    }

    #[pyclass(unsendable, name = "RandPrintablesGenerator")]
    #[derive(Debug, Clone)]
    /// Python class for RandPrintablesGenerator
    pub struct PythonRandPrintablesGenerator {
        /// Rust wrapped RandPrintablesGenerator object
        pub inner: RandPrintablesGenerator<PythonStdState>,
    }

    #[pymethods]
    impl PythonRandPrintablesGenerator {
        #[new]
        fn new(max_size: usize) -> Self {
            Self {
                inner: RandPrintablesGenerator::new(max_size),
            }
        }

        fn generate(&mut self, state: &mut PythonStdStateWrapper) -> Vec<u8> {
            self.inner
                .generate(state.unwrap_mut())
                .expect("PythonRandPrintablesGenerator::generate failed")
                .bytes()
                .to_vec()
        }

        fn as_generator(slf: Py<Self>) -> PythonGenerator {
            PythonGenerator::new_rand_printables(slf)
        }
    }

    #[derive(Debug, Clone)]
    enum PythonGeneratorWrapper {
        RandBytes(Py<PythonRandBytesGenerator>),
        RandPrintables(Py<PythonRandPrintablesGenerator>),
        Python(PyObjectGenerator),
    }

    /// Rand Trait binding
    #[pyclass(unsendable, name = "Generator")]
    #[derive(Debug, Clone)]
    pub struct PythonGenerator {
        wrapper: PythonGeneratorWrapper,
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_mut_body!($wrapper, $name, $body, PythonGeneratorWrapper,
                { RandBytes, RandPrintables },
                {
                    Python(py_wrapper) => {
                        let $name = py_wrapper;
                        $body
                    }
                }
            )
        };
    }

    #[pymethods]
    impl PythonGenerator {
        #[staticmethod]
        fn new_rand_bytes(py_gen: Py<PythonRandBytesGenerator>) -> Self {
            Self {
                wrapper: PythonGeneratorWrapper::RandBytes(py_gen),
            }
        }

        #[staticmethod]
        fn new_rand_printables(py_gen: Py<PythonRandPrintablesGenerator>) -> Self {
            Self {
                wrapper: PythonGeneratorWrapper::RandPrintables(py_gen),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonGeneratorWrapper::Python(PyObjectGenerator::new(obj)),
            }
        }

        #[must_use]
        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonGeneratorWrapper::Python(pyo) => Some(pyo.inner.clone()),
                _ => None,
            }
        }
    }

    impl Generator<BytesInput, PythonStdState> for PythonGenerator {
        fn generate(&mut self, state: &mut PythonStdState) -> Result<BytesInput, Error> {
            unwrap_me_mut!(self.wrapper, g, { g.generate(state) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonRandBytesGenerator>()?;
        m.add_class::<PythonRandPrintablesGenerator>()?;
        m.add_class::<PythonGenerator>()?;
        Ok(())
    }
}
