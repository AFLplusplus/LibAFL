//! Observers give insights about runs of a target, such as coverage, timing, stack depth, and more.

pub mod map;
pub use map::*;

pub mod cmp;
pub use cmp::*;

#[cfg(feature = "std")]
pub mod stdio;
#[cfg(feature = "std")]
pub use stdio::{StdErrObserver, StdOutObserver};

#[cfg(feature = "std")]
pub mod stacktrace;
#[cfg(feature = "std")]
pub use stacktrace::*;

pub mod concolic;

#[cfg(unstable_feature)]
pub mod owned;
#[cfg(unstable_feature)]
pub use owned::*;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt::Debug, time::Duration};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        current_time,
        ownedref::OwnedRefMut,
        tuples::{MatchName, Named},
    },
    executors::ExitKind,
    Error,
};

/// Observers observe different information about the target.
/// They can then be used by various sorts of feedback.
pub trait Observer<I, S>: Named + Debug {
    /// The testcase finished execution, calculate any changes.
    /// Reserved for future use.
    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts.
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes.
    #[inline]
    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called right before execution starts in the child process, if any.
    #[inline]
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finishes in the child process, if any.
    #[inline]
    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A haskell-style tuple of observers
pub trait ObserversTuple<I, S>: MatchName + Debug {
    /// This is called right before the next execution.
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error>;

    /// This is called right after the last execution
    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;

    /// This is called right before the next execution in the child process, if any.
    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error>;

    /// This is called right after the last execution in the child process, if any.
    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error>;
}

impl<I, S> ObserversTuple<I, S> for () {
    fn pre_exec_all(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn pre_exec_child_all(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_child_all(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, I, S> ObserversTuple<I, S> for (Head, Tail)
where
    Head: Observer<I, S>,
    Tail: ObserversTuple<I, S>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.0.pre_exec(state, input)?;
        self.1.pre_exec_all(state, input)
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec(state, input, exit_kind)?;
        self.1.post_exec_all(state, input, exit_kind)
    }

    fn pre_exec_child_all(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.0.pre_exec_child(state, input)?;
        self.1.pre_exec_child_all(state, input)
    }

    fn post_exec_child_all(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.0.post_exec_child(state, input, exit_kind)?;
        self.1.post_exec_child_all(state, input, exit_kind)
    }
}

/// A trait for obervers with a hash field
pub trait ObserverWithHashField {
    /// get the value of the hash field
    fn hash(&self) -> &Option<u64>;
    /// update the hash field with the given value
    fn update_hash(&mut self, hash: u64);
    /// clears the current value of the hash and sets it to None
    fn clear_hash(&mut self);
}
/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeObserver {
    name: String,
    start_time: Duration,
    last_runtime: Option<Duration>,
}

impl TimeObserver {
    /// Creates a new [`TimeObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: name.to_string(),
            start_time: Duration::from_secs(0),
            last_runtime: None,
        }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn last_runtime(&self) -> &Option<Duration> {
        &self.last_runtime
    }
}

impl<I, S> Observer<I, S> for TimeObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.last_runtime = None;
        self.start_time = current_time();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.last_runtime = current_time().checked_sub(self.start_time);
        Ok(())
    }
}

impl Named for TimeObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

/// A simple observer with a list of things.
#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: serde::de::DeserializeOwned")]
pub struct ListObserver<'a, T>
where
    T: Debug + Serialize,
{
    name: String,
    /// The list
    list: OwnedRefMut<'a, Vec<T>>,
}

impl<'a, T> ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    /// Creates a new [`ListObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, list: &'a mut Vec<T>) -> Self {
        Self {
            name: name.to_string(),
            list: OwnedRefMut::Ref(list),
        }
    }

    /// Get a list ref
    #[must_use]
    pub fn list(&self) -> &Vec<T> {
        self.list.as_ref()
    }

    /// Get a list mut
    #[must_use]
    pub fn list_mut(&mut self) -> &mut Vec<T> {
        self.list.as_mut()
    }
}

impl<'a, I, S, T> Observer<I, S> for ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.list.as_mut().clear();
        Ok(())
    }
}

impl<'a, T> Named for ListObserver<'a, T>
where
    T: Debug + Serialize + serde::de::DeserializeOwned,
{
    fn name(&self) -> &str {
        &self.name
    }
}

/// `Observer` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use super::{CmpMap, Debug, MapObserver, Observer, ObserversTuple, String, Vec};
    use crate::bolts::tuples::{type_eq, MatchName, Named};
    use crate::executors::ExitKind;
    use crate::inputs::BytesInput;
    use crate::inputs::HasBytesVec;
    use crate::observers::map::pybind::{
        PythonMapObserverI16, PythonMapObserverI32, PythonMapObserverI64, PythonMapObserverI8,
        PythonMapObserverU16, PythonMapObserverU32, PythonMapObserverU64, PythonMapObserverU8,
        PythonMapObserverWrapperI16, PythonMapObserverWrapperI32, PythonMapObserverWrapperI64,
        PythonMapObserverWrapperI8, PythonMapObserverWrapperU16, PythonMapObserverWrapperU32,
        PythonMapObserverWrapperU64, PythonMapObserverWrapperU8,
    };
    use crate::pybind::SerdePy;
    use crate::state::pybind::{PythonStdState, PythonStdStateWrapper};
    use crate::Error;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::cell::UnsafeCell;

    #[derive(Debug)]
    pub struct PyObjectObserver {
        inner: PyObject,
        name: UnsafeCell<String>,
    }

    impl Clone for PyObjectObserver {
        fn clone(&self) -> PyObjectObserver {
            PyObjectObserver {
                inner: self.inner.clone(),
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    impl PyObjectObserver {
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            PyObjectObserver {
                inner: obj,
                name: UnsafeCell::new(String::new()),
            }
        }
    }

    crate::impl_serde_pyobjectwrapper!(PyObjectObserver, inner);

    impl Named for PyObjectObserver {
        fn name(&self) -> &str {
            let s = Python::with_gil(|py| -> PyResult<String> {
                let s: String = self.inner.call_method0(py, "name")?.extract(py)?;
                Ok(s)
            })
            .unwrap();
            unsafe {
                *self.name.get() = s;
                &*self.name.get()
            }
        }
    }

    impl Observer<BytesInput, PythonStdState> for PyObjectObserver {
        fn flush(&mut self) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method0(py, "flush")?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn pre_exec(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "pre_exec",
                    (PythonStdStateWrapper::wrap(state), input.bytes()),
                )?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn post_exec(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            _exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "post_exec",
                    (PythonStdStateWrapper::wrap(state), input.bytes()),
                )?; // TODO add exit kind
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn pre_exec_child(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "pre_exec_child",
                    (PythonStdStateWrapper::wrap(state), input.bytes()),
                )?;
                Ok(())
            })
            .unwrap();
            Ok(())
        }

        fn post_exec_child(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            _exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "post_exec_child",
                    (PythonStdStateWrapper::wrap(state), input.bytes()),
                )?; // TODO add exit kind
                Ok(())
            })
            .unwrap();
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub enum PythonObserverWrapper {
        MapI8(SerdePy<PythonMapObserverI8>),
        MapI16(SerdePy<PythonMapObserverI16>),
        MapI32(SerdePy<PythonMapObserverI32>),
        MapI64(SerdePy<PythonMapObserverI64>),
        MapU8(SerdePy<PythonMapObserverU8>),
        MapU16(SerdePy<PythonMapObserverU16>),
        MapU32(SerdePy<PythonMapObserverU32>),
        MapU64(SerdePy<PythonMapObserverU64>),
        Python(PyObjectObserver),
    }

    #[pyclass(unsendable, name = "Observer")]
    #[derive(Serialize, Deserialize, Clone, Debug)]
    /// Observer Trait binding
    pub struct PythonObserver {
        pub wrapper: PythonObserverWrapper,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $name:ident, $body:block) => {
            match &$wrapper {
                PythonObserverWrapper::MapI8(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let borrowed = py_wrapper.borrow(py);
                    Ok(crate::mapob_unwrap_me!(
                        PythonMapObserverWrapperI8,
                        borrowed.wrapper,
                        $name,
                        $body
                    ))
                })
                .unwrap(),
                PythonObserverWrapper::MapI16(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperI16,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapI32(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperI32,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapI64(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperI64,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU8(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let borrowed = py_wrapper.borrow(py);
                    Ok(crate::mapob_unwrap_me!(
                        PythonMapObserverWrapperU8,
                        borrowed.wrapper,
                        $name,
                        $body
                    ))
                })
                .unwrap(),
                PythonObserverWrapper::MapU16(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperU16,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU32(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperU32,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU64(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let borrowed = py_wrapper.borrow(py);
                        Ok(crate::mapob_unwrap_me!(
                            PythonMapObserverWrapperU64,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::Python(py_wrapper) => {
                    let $name = py_wrapper;
                    $body
                }
            }
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            match &mut $wrapper {
                PythonObserverWrapper::MapI8(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let mut borrowed = py_wrapper.borrow_mut(py);
                    Ok(crate::mapob_unwrap_me_mut!(
                        PythonMapObserverWrapperI8,
                        borrowed.wrapper,
                        $name,
                        $body
                    ))
                })
                .unwrap(),
                PythonObserverWrapper::MapI16(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperI16,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapI32(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperI32,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapI64(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperI64,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU8(py_wrapper) => Python::with_gil(|py| -> PyResult<_> {
                    let mut borrowed = py_wrapper.borrow_mut(py);
                    Ok(crate::mapob_unwrap_me_mut!(
                        PythonMapObserverWrapperU8,
                        borrowed.wrapper,
                        $name,
                        $body
                    ))
                })
                .unwrap(),
                PythonObserverWrapper::MapU16(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperU16,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU32(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperU32,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::MapU64(py_wrapper) => {
                    Python::with_gil(|py| -> PyResult<_> {
                        let mut borrowed = py_wrapper.borrow_mut(py);
                        Ok(crate::mapob_unwrap_me_mut!(
                            PythonMapObserverWrapperU64,
                            borrowed.wrapper,
                            $name,
                            $body
                        ))
                    })
                    .unwrap()
                }
                PythonObserverWrapper::Python(py_wrapper) => {
                    let $name = py_wrapper;
                    $body
                }
            }
        };
    }

    #[pymethods]
    impl PythonObserver {
        #[staticmethod]
        #[must_use]
        pub fn new_map_i8(map_observer: Py<PythonMapObserverI8>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapI8(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_i16(map_observer: Py<PythonMapObserverI16>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapI16(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_i32(map_observer: Py<PythonMapObserverI32>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapI32(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_i64(map_observer: Py<PythonMapObserverI64>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapI64(map_observer.into()),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_map_u8(map_observer: Py<PythonMapObserverU8>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapU8(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_u16(map_observer: Py<PythonMapObserverU16>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapU16(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_u32(map_observer: Py<PythonMapObserverU32>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapU32(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_map_u64(map_observer: Py<PythonMapObserverU64>) -> Self {
            Self {
                wrapper: PythonObserverWrapper::MapU64(map_observer.into()),
            }
        }
        #[staticmethod]
        #[must_use]
        pub fn new_py(py_observer: PyObject) -> Self {
            Self {
                wrapper: PythonObserverWrapper::Python(PyObjectObserver::new(py_observer)),
            }
        }

        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonObserverWrapper::Python(pyo) => Some(pyo.inner.clone()),
                _ => None,
            }
        }
    }

    impl Named for PythonObserver {
        fn name(&self) -> &str {
            let ptr = unwrap_me!(self.wrapper, o, { o.name() as *const str });
            unsafe { ptr.as_ref().unwrap() }
        }
    }

    impl Observer<BytesInput, PythonStdState> for PythonObserver {
        fn flush(&mut self) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, o, {
                Observer::<BytesInput, PythonStdState>::flush(o)
            })
        }

        fn pre_exec(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, o, { o.pre_exec(state, input) })
        }

        fn post_exec(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, o, { o.post_exec(state, input, exit_kind) })
        }

        fn pre_exec_child(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, o, { o.pre_exec_child(state, input) })
        }

        fn post_exec_child(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, o, {
                o.post_exec_child(state, input, exit_kind)
            })
        }
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[pyclass(unsendable, name = "ObserversTuple")]
    pub struct PythonObserversTuple {
        list: Vec<PythonObserver>,
    }

    #[pymethods]
    impl PythonObserversTuple {
        #[new]
        fn new(list: Vec<PythonObserver>) -> Self {
            Self { list }
        }

        fn len(&self) -> usize {
            self.list.len()
        }

        fn __getitem__(&self, idx: usize) -> PythonObserver {
            self.list[idx].clone()
        }

        #[pyo3(name = "match_name")]
        fn pymatch_name(&self, name: &str) -> Option<PythonObserver> {
            for ob in &self.list {
                if ob.name() == name {
                    return Some(ob.clone());
                }
            }
            None
        }
    }

    impl ObserversTuple<BytesInput, PythonStdState> for PythonObserversTuple {
        fn pre_exec_all(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            for ob in &mut self.list {
                ob.pre_exec(state, input)?;
            }
            Ok(())
        }

        fn post_exec_all(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            for ob in &mut self.list {
                ob.post_exec(state, input, exit_kind)?;
            }
            Ok(())
        }

        fn pre_exec_child_all(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
        ) -> Result<(), Error> {
            for ob in &mut self.list {
                ob.pre_exec_child(state, input)?;
            }
            Ok(())
        }

        fn post_exec_child_all(
            &mut self,
            state: &mut PythonStdState,
            input: &BytesInput,
            exit_kind: &ExitKind,
        ) -> Result<(), Error> {
            for ob in &mut self.list {
                ob.post_exec_child(state, input, exit_kind)?;
            }
            Ok(())
        }
    }

    impl MatchName for PythonObserversTuple {
        fn match_name<T>(&self, name: &str) -> Option<&T> {
            unsafe {
                let mut r = None;
                for ob in &self.list {
                    Python::with_gil(|py| -> PyResult<_> {
                        match &ob.wrapper {
                            PythonObserverWrapper::MapI8(py_wrapper) => {
                                if type_eq::<PythonMapObserverI8, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapI16(py_wrapper) => {
                                if type_eq::<PythonMapObserverI16, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapI32(py_wrapper) => {
                                if type_eq::<PythonMapObserverI32, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapI64(py_wrapper) => {
                                if type_eq::<PythonMapObserverI64, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }

                            PythonObserverWrapper::MapU8(py_wrapper) => {
                                if type_eq::<PythonMapObserverU8, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapU16(py_wrapper) => {
                                if type_eq::<PythonMapObserverU16, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapU32(py_wrapper) => {
                                if type_eq::<PythonMapObserverU32, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::MapU64(py_wrapper) => {
                                if type_eq::<PythonMapObserverU64, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow(py)) as *const T)
                                        .as_ref()
                                }
                            }
                            PythonObserverWrapper::Python(py_wrapper) => {
                                if type_eq::<PyObjectObserver, T>() && py_wrapper.name() == name {
                                    r = (py_wrapper as *const _ as *const T).as_ref();
                                }
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                r
            }
        }

        fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
            unsafe {
                let mut r = None;
                for ob in &mut self.list {
                    Python::with_gil(|py| -> PyResult<_> {
                        match &mut ob.wrapper {
                            PythonObserverWrapper::MapI8(py_wrapper) => {
                                if type_eq::<PythonMapObserverI8, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapI16(py_wrapper) => {
                                if type_eq::<PythonMapObserverI16, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapI32(py_wrapper) => {
                                if type_eq::<PythonMapObserverI32, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapI64(py_wrapper) => {
                                if type_eq::<PythonMapObserverI64, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }

                            PythonObserverWrapper::MapU8(py_wrapper) => {
                                if type_eq::<PythonMapObserverU8, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapU16(py_wrapper) => {
                                if type_eq::<PythonMapObserverU16, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapU32(py_wrapper) => {
                                if type_eq::<PythonMapObserverU32, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::MapU64(py_wrapper) => {
                                if type_eq::<PythonMapObserverU64, T>()
                                    && py_wrapper.borrow(py).name() == name
                                {
                                    r = (std::ptr::addr_of!(*(*py_wrapper).borrow_mut(py))
                                        as *mut T)
                                        .as_mut()
                                }
                            }
                            PythonObserverWrapper::Python(py_wrapper) => {
                                if type_eq::<PyObjectObserver, T>() && py_wrapper.name() == name {
                                    r = (py_wrapper as *mut _ as *mut T).as_mut();
                                }
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
                }
                r
            }
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonObserver>()?;
        m.add_class::<PythonObserversTuple>()?;
        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        bolts::tuples::{tuple_list, tuple_list_type, Named},
        observers::{StdMapObserver, TimeObserver},
    };

    static mut MAP: [u32; 4] = [0; 4];

    #[test]
    fn test_observer_serde() {
        let obv = tuple_list!(
            TimeObserver::new("time"),
            StdMapObserver::new("map", unsafe { &mut MAP })
        );
        let vec = postcard::to_allocvec(&obv).unwrap();
        println!("{:?}", vec);
        let obv2: tuple_list_type!(TimeObserver, StdMapObserver<u32>) =
            postcard::from_bytes(&vec).unwrap();
        assert_eq!(obv.0.name(), obv2.0.name());
    }
}
