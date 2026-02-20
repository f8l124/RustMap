use std::sync::Arc;

use pyo3::exceptions::PyStopAsyncIteration;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rustmap_core::{CancellationToken, ScanEvent};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::error::RustmapError;
use crate::result::{PyHostScanResult, PyScanResult};

/// Rust-side representation of a stream event, converted to Python types only
/// when the GIL is already held (at the pyo3-async-runtimes boundary) instead
/// of acquiring it redundantly inside the async future.
enum StreamEvent {
    HostResult {
        result: Box<rustmap_types::HostScanResult>,
        hosts_completed: usize,
        hosts_total: usize,
    },
    Complete {
        result: Box<rustmap_types::ScanResult>,
    },
    DiscoveryComplete {
        hosts_total: usize,
    },
}

impl<'py> IntoPyObject<'py> for StreamEvent {
    type Target = PyDict;
    type Output = Bound<'py, PyDict>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        let dict = PyDict::new(py);
        match self {
            StreamEvent::HostResult {
                result,
                hosts_completed,
                hosts_total,
            } => {
                dict.set_item("type", "host_result")?;
                let host_result = PyHostScanResult { inner: *result };
                dict.set_item("result", host_result.into_pyobject(py)?)?;
                dict.set_item("completed", hosts_completed)?;
                dict.set_item("total", hosts_total)?;
            }
            StreamEvent::Complete { result } => {
                dict.set_item("type", "complete")?;
                let scan_result = PyScanResult::from_inner(*result);
                dict.set_item("result", scan_result.into_pyobject(py)?)?;
            }
            StreamEvent::DiscoveryComplete { hosts_total } => {
                dict.set_item("type", "discovery_complete")?;
                dict.set_item("hosts_total", hosts_total)?;
            }
        }
        Ok(dict)
    }
}

#[pyclass(name = "ScanStream")]
pub struct PyScanStream {
    rx: Arc<Mutex<mpsc::Receiver<ScanEvent>>>,
    pub(crate) cancel_token: CancellationToken,
}

impl PyScanStream {
    pub fn new(rx: mpsc::Receiver<ScanEvent>, cancel_token: CancellationToken) -> Self {
        Self {
            rx: Arc::new(Mutex::new(rx)),
            cancel_token,
        }
    }
}

#[pymethods]
impl PyScanStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(ScanEvent::HostResult {
                    result,
                    hosts_completed,
                    hosts_total,
                    ..
                }) => Ok(StreamEvent::HostResult {
                    result,
                    hosts_completed,
                    hosts_total,
                }),
                Some(ScanEvent::Complete(result)) => Ok(StreamEvent::Complete { result }),
                Some(ScanEvent::DiscoveryComplete { hosts_total }) => {
                    Ok(StreamEvent::DiscoveryComplete { hosts_total })
                }
                Some(ScanEvent::Error(msg)) => Err(RustmapError::new_err(msg)),
                None => Err(PyStopAsyncIteration::new_err("stream finished")),
            }
        })
    }

    /// Cancel the underlying scan.
    #[pyo3(name = "cancel")]
    fn cancel(&self) {
        self.cancel_token.cancel();
    }
}
