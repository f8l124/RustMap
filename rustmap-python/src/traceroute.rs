use pyo3::prelude::*;
use rustmap_types::{TracerouteHop, TracerouteResult};

use crate::host::PyHost;

#[pyclass(name = "TracerouteResult", frozen)]
pub struct PyTracerouteResult {
    inner: TracerouteResult,
}

#[pymethods]
impl PyTracerouteResult {
    #[getter]
    fn target(&self) -> PyHost {
        PyHost::from_inner(self.inner.target.clone())
    }
    #[getter]
    fn hops(&self) -> Vec<PyTracerouteHop> {
        self.inner
            .hops
            .iter()
            .map(|h| PyTracerouteHop { inner: h.clone() })
            .collect()
    }
    #[getter]
    fn port(&self) -> u16 {
        self.inner.port
    }
    #[getter]
    fn protocol(&self) -> String {
        self.inner.protocol.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "TracerouteResult(target='{}', hops={})",
            self.inner.target.ip,
            self.inner.hops.len()
        )
    }
}

impl PyTracerouteResult {
    pub fn from_inner(inner: TracerouteResult) -> Self {
        Self { inner }
    }
}

#[pyclass(name = "TracerouteHop", frozen)]
pub struct PyTracerouteHop {
    inner: TracerouteHop,
}

#[pymethods]
impl PyTracerouteHop {
    #[getter]
    fn ttl(&self) -> u8 {
        self.inner.ttl
    }
    #[getter]
    fn ip(&self) -> Option<String> {
        self.inner.ip.map(|ip| ip.to_string())
    }
    #[getter]
    fn hostname(&self) -> Option<String> {
        self.inner.hostname.clone()
    }
    /// RTT in seconds (float), or None if hop timed out.
    #[getter]
    fn rtt(&self) -> Option<f64> {
        self.inner.rtt.map(|d| d.as_secs_f64())
    }

    fn __repr__(&self) -> String {
        let ip = self
            .inner
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "*".to_string());
        let rtt = self
            .inner
            .rtt
            .map(|d| format!("{:.3}ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "*".to_string());
        format!("TracerouteHop(ttl={}, ip='{}', rtt={})", self.inner.ttl, ip, rtt)
    }
}
