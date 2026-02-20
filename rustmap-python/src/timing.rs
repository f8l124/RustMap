use pyo3::prelude::*;
use rustmap_types::TimingSnapshot;

#[pyclass(name = "TimingSnapshot", frozen)]
pub struct PyTimingSnapshot {
    inner: TimingSnapshot,
}

#[pymethods]
impl PyTimingSnapshot {
    #[getter]
    fn srtt_us(&self) -> Option<u64> {
        self.inner.srtt_us
    }
    #[getter]
    fn rto_us(&self) -> u64 {
        self.inner.rto_us
    }
    #[getter]
    fn rttvar_us(&self) -> Option<u64> {
        self.inner.rttvar_us
    }
    #[getter]
    fn cwnd(&self) -> usize {
        self.inner.cwnd
    }
    #[getter]
    fn probes_sent(&self) -> u64 {
        self.inner.probes_sent
    }
    #[getter]
    fn probes_responded(&self) -> u64 {
        self.inner.probes_responded
    }
    #[getter]
    fn probes_timed_out(&self) -> u64 {
        self.inner.probes_timed_out
    }
    #[getter]
    fn loss_rate(&self) -> f64 {
        self.inner.loss_rate
    }

    fn __repr__(&self) -> String {
        format!(
            "TimingSnapshot(srtt={}us, loss={:.1}%, sent={})",
            self.inner.srtt_us.unwrap_or(0),
            self.inner.loss_rate * 100.0,
            self.inner.probes_sent,
        )
    }
}

impl PyTimingSnapshot {
    pub fn from_inner(inner: TimingSnapshot) -> Self {
        Self { inner }
    }
}
