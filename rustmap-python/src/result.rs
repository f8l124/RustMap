use std::sync::OnceLock;

use pyo3::prelude::*;
use rustmap_types::{HostScanResult, HostStatus, PortState, ScanResult};

use crate::enums::{host_status_to_str, scan_type_to_str};
use crate::host::PyHost;
use crate::os::PyOsFingerprint;
use crate::port::PyPort;
use crate::script::PyScriptResult;
use crate::timing::PyTimingSnapshot;
use crate::traceroute::PyTracerouteResult;

#[pyclass(name = "ScanResult", frozen)]
pub struct PyScanResult {
    inner: ScanResult,
    /// Cached converted hosts list. Computed lazily on first access so that
    /// repeated calls to the `hosts` getter avoid re-cloning every
    /// `HostScanResult`.
    cached_hosts: OnceLock<Vec<HostScanResult>>,
}

#[pymethods]
impl PyScanResult {
    #[getter]
    fn hosts(&self) -> Vec<PyHostScanResult> {
        let cached = self.cached_hosts.get_or_init(|| self.inner.hosts.clone());
        cached
            .iter()
            .map(|h| PyHostScanResult { inner: h.clone() })
            .collect()
    }

    /// Total scan duration in seconds.
    #[getter]
    fn total_duration(&self) -> f64 {
        self.inner.total_duration.as_secs_f64()
    }

    #[getter]
    fn scan_type(&self) -> String {
        scan_type_to_str(self.inner.scan_type).to_string()
    }

    #[getter]
    fn num_services(&self) -> usize {
        self.inner.num_services
    }

    #[getter]
    fn command_args(&self) -> Option<String> {
        self.inner.command_args.clone()
    }

    /// Number of hosts that are up (or unknown from -Pn).
    fn hosts_up(&self) -> usize {
        self.inner
            .hosts
            .iter()
            .filter(|h| h.host_status == HostStatus::Up || h.host_status == HostStatus::Unknown)
            .count()
    }

    /// Number of hosts that are down.
    fn hosts_down(&self) -> usize {
        self.inner
            .hosts
            .iter()
            .filter(|h| h.host_status == HostStatus::Down)
            .count()
    }

    /// Convert result to a Python dict via JSON roundtrip.
    fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let json_str = serde_json::to_string(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let json_mod = py.import("json")?;
        json_mod
            .call_method1("loads", (json_str,))
            .map(|v| v.unbind())
    }

    /// Serialize result to pretty-printed JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "ScanResult(hosts={}, duration={:.2}s, scan_type='{}')",
            self.inner.hosts.len(),
            self.inner.total_duration.as_secs_f64(),
            scan_type_to_str(self.inner.scan_type)
        )
    }

    fn __len__(&self) -> usize {
        self.inner.hosts.len()
    }
}

impl PyScanResult {
    pub fn from_inner(inner: ScanResult) -> Self {
        Self {
            inner,
            cached_hosts: OnceLock::new(),
        }
    }
}

#[pyclass(name = "HostScanResult", frozen)]
pub struct PyHostScanResult {
    pub(crate) inner: HostScanResult,
}

#[pymethods]
impl PyHostScanResult {
    #[getter]
    fn host(&self) -> PyHost {
        PyHost::from_inner(self.inner.host.clone())
    }
    #[getter]
    fn ip(&self) -> String {
        self.inner.host.ip.to_string()
    }
    #[getter]
    fn hostname(&self) -> Option<String> {
        self.inner.host.hostname.clone()
    }
    #[getter]
    fn ports(&self) -> Vec<PyPort> {
        self.inner
            .ports
            .iter()
            .map(|p| PyPort::from_inner(p.clone()))
            .collect()
    }
    #[getter]
    fn status(&self) -> String {
        host_status_to_str(self.inner.host_status).to_string()
    }
    /// Scan duration in seconds.
    #[getter]
    fn scan_duration(&self) -> f64 {
        self.inner.scan_duration.as_secs_f64()
    }
    /// Discovery latency in seconds, or None.
    #[getter]
    fn discovery_latency(&self) -> Option<f64> {
        self.inner.discovery_latency.map(|d| d.as_secs_f64())
    }
    #[getter]
    fn os_fingerprint(&self) -> Option<PyOsFingerprint> {
        self.inner
            .os_fingerprint
            .clone()
            .map(PyOsFingerprint::from_inner)
    }
    #[getter]
    fn traceroute(&self) -> Option<PyTracerouteResult> {
        self.inner
            .traceroute
            .clone()
            .map(PyTracerouteResult::from_inner)
    }
    #[getter]
    fn timing_snapshot(&self) -> Option<PyTimingSnapshot> {
        self.inner
            .timing_snapshot
            .clone()
            .map(PyTimingSnapshot::from_inner)
    }
    #[getter]
    fn script_results(&self) -> Vec<PyScriptResult> {
        self.inner
            .host_script_results
            .iter()
            .map(|sr| PyScriptResult::from_inner(sr.clone()))
            .collect()
    }
    #[getter]
    fn scan_error(&self) -> Option<String> {
        self.inner.scan_error.clone()
    }
    #[getter]
    fn mtu(&self) -> Option<u16> {
        self.inner.mtu
    }

    /// Return only ports with state == open.
    fn open_ports(&self) -> Vec<PyPort> {
        self.inner
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .map(|p| PyPort::from_inner(p.clone()))
            .collect()
    }

    fn __repr__(&self) -> String {
        let open_count = self.inner.ports.iter().filter(|p| p.state == PortState::Open).count();
        format!(
            "HostScanResult(ip='{}', status='{}', ports={}, open={})",
            self.inner.host.ip,
            host_status_to_str(self.inner.host_status),
            self.inner.ports.len(),
            open_count,
        )
    }
}
