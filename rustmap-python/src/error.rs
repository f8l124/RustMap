use pyo3::exceptions::PyRuntimeError;

pyo3::create_exception!(rustmap, RustmapError, PyRuntimeError);

/// Convert an EngineError to a PyErr (RustmapError).
pub fn engine_err_to_pyerr(err: rustmap_core::EngineError) -> pyo3::PyErr {
    RustmapError::new_err(err.to_string())
}
