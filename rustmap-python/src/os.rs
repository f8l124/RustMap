use pyo3::prelude::*;
use rustmap_types::OsFingerprint;

#[pyclass(name = "OsFingerprint", frozen)]
pub struct PyOsFingerprint {
    inner: OsFingerprint,
}

#[pymethods]
impl PyOsFingerprint {
    #[getter]
    fn os_family(&self) -> Option<String> {
        self.inner.os_family.clone()
    }
    #[getter]
    fn os_generation(&self) -> Option<String> {
        self.inner.os_generation.clone()
    }
    #[getter]
    fn accuracy(&self) -> Option<u8> {
        self.inner.accuracy
    }

    fn __repr__(&self) -> String {
        let family = self.inner.os_family.as_deref().unwrap_or("unknown");
        let generation = self.inner.os_generation.as_deref().unwrap_or("");
        let acc = self.inner.accuracy.map(|a| format!(" {}%", a)).unwrap_or_default();
        format!("OsFingerprint(family='{}', generation='{}'{acc})", family, generation)
    }
}

impl PyOsFingerprint {
    pub fn from_inner(inner: OsFingerprint) -> Self {
        Self { inner }
    }
}
