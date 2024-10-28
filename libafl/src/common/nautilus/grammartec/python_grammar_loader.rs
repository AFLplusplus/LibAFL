// Nautilus
// Copyright (C) 2024  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

use std::{string::String, vec::Vec};

use pyo3::{prelude::*, pyclass, types::IntoPyDict};

use crate::nautilus::grammartec::context::Context;

#[pyclass]
struct PyContext {
    ctx: Context,
}
impl PyContext {
    fn get_context(&self) -> Context {
        self.ctx.clone()
    }
}

#[pymethods]
impl PyContext {
    #[new]
    fn new() -> Self {
        PyContext {
            ctx: Context::new(),
        }
    }

    fn rule(&mut self, py: Python, nt: &str, format: Bound<PyAny>) -> PyResult<()> {
        if let Ok(s) = format.extract::<&str>() {
            self.ctx.add_rule(nt, s.as_bytes());
        } else if let Ok(s) = format.extract::<&[u8]>() {
            self.ctx.add_rule(nt, s);
        } else {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "format argument should be string or bytes",
            ));
        }
        return Ok(());
    }

    fn script(&mut self, nt: &str, nts: Vec<String>, script: PyObject) {
        self.ctx.add_script(nt, &nts, script);
    }

    fn regex(&mut self, nt: &str, regex: &str) {
        self.ctx.add_regex(nt, regex);
    }
}

fn main_(py: Python, grammar: &str) -> PyResult<Context> {
    let py_ctx = Bound::new(py, PyContext::new()).unwrap();
    let locals = [("ctx", &py_ctx)].into_py_dict_bound(py);
    py.run_bound(grammar, None, Some(&locals))?;
    return Ok(py_ctx.borrow().get_context());
}

pub fn load_python_grammar(grammar: &str) -> Context {
    return Python::with_gil(|py| {
        main_(py, grammar)
            .map_err(|e| e.print_and_set_sys_last_vars(py))
            .unwrap()
    });
}
