use pyo3::prelude::*;
use pyo3::types::PyDict;
use rustmap_types::{ScriptResult, ScriptValue};

#[pyclass(name = "ScriptResult", frozen)]
pub struct PyScriptResult {
    inner: ScriptResult,
}

#[pymethods]
impl PyScriptResult {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }
    #[getter]
    fn output(&self) -> String {
        self.inner.output.clone()
    }
    #[getter]
    fn elements<'py>(&self, py: Python<'py>) -> Option<PyObject> {
        self.inner.elements.as_ref().map(|v| script_value_to_py(py, v))
    }

    fn __repr__(&self) -> String {
        format!(
            "ScriptResult(id='{}', output='{}')",
            self.inner.id,
            truncate(&self.inner.output, 60)
        )
    }
}

impl PyScriptResult {
    pub fn from_inner(inner: ScriptResult) -> Self {
        Self { inner }
    }
}

/// Convert ScriptValue to native Python objects (dict, list, str, float, bool).
fn script_value_to_py(py: Python<'_>, val: &ScriptValue) -> PyObject {
    match val {
        ScriptValue::String(s) => s.into_pyobject(py).unwrap().into_any().unbind(),
        ScriptValue::Number(n) => n.into_pyobject(py).unwrap().into_any().unbind(),
        ScriptValue::Bool(b) => b.into_pyobject(py).unwrap().to_owned().into_any().unbind(),
        ScriptValue::List(items) => {
            let list: Vec<PyObject> = items.iter().map(|v| script_value_to_py(py, v)).collect();
            list.into_pyobject(py).unwrap().into_any().unbind()
        }
        ScriptValue::Map(pairs) => {
            let dict = PyDict::new(py);
            for (k, v) in pairs {
                let _ = dict.set_item(k, script_value_to_py(py, v));
            }
            dict.into_any().unbind()
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max_len)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..end])
}
