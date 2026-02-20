use pyo3::prelude::*;
use tokio::sync::mpsc;

mod config;
mod enums;
pub mod error;
mod host;
mod os;
mod port;
mod result;
mod script;
mod stream;
mod timing;
mod traceroute;

use config::PyScanConfig;
use error::RustmapError;
use result::PyScanResult;
use stream::PyScanStream;

/// Returns a lazily-initialized global Tokio runtime shared across all
/// synchronous scan calls, avoiding the overhead and resource waste of
/// creating a new runtime for every invocation.
fn global_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("failed to create Tokio runtime")
    })
}

/// Convenience scan: `result = rustmap.scan("192.168.1.1", ports="80,443")`.
///
/// Blocks until the scan completes. The GIL is released during the scan.
#[pyfunction]
#[pyo3(signature = (target, *, ports=None, scan_type=None, timeout=None, service_detection=false, os_detection=false, timing=None, skip_discovery=false))]
#[allow(clippy::too_many_arguments)]
fn scan(
    py: Python<'_>,
    target: &str,
    ports: Option<&str>,
    scan_type: Option<&str>,
    timeout: Option<f64>,
    service_detection: bool,
    os_detection: bool,
    timing: Option<u8>,
    skip_discovery: bool,
) -> PyResult<PyScanResult> {
    let cfg = build_config(
        &[target.to_string()],
        ports,
        scan_type,
        timeout,
        service_detection,
        os_detection,
        timing,
        skip_discovery,
    )?;

    let result = py
        .allow_threads(|| {
            global_runtime()
                .block_on(rustmap_core::ScanEngine::run(&cfg))
                .map_err(|e| e.to_string())
        })
        .map_err(|e: String| RustmapError::new_err(e))?;

    Ok(PyScanResult::from_inner(result))
}

/// Scan with full config: `result = rustmap.scan_with_config(config)`.
#[pyfunction]
fn scan_with_config(py: Python<'_>, config: &PyScanConfig) -> PyResult<PyScanResult> {
    let scan_config = config.to_scan_config()?;

    let result = py
        .allow_threads(|| {
            global_runtime()
                .block_on(rustmap_core::ScanEngine::run(&scan_config))
                .map_err(|e| e.to_string())
        })
        .map_err(|e: String| RustmapError::new_err(e))?;

    Ok(PyScanResult::from_inner(result))
}

/// Async scan: `result = await rustmap.async_scan("192.168.1.1", ports="80,443")`.
#[pyfunction]
#[pyo3(signature = (target, *, ports=None, scan_type=None, timeout=None, service_detection=false, os_detection=false, timing=None, skip_discovery=false))]
#[allow(clippy::too_many_arguments)]
fn async_scan<'py>(
    py: Python<'py>,
    target: &str,
    ports: Option<&str>,
    scan_type: Option<&str>,
    timeout: Option<f64>,
    service_detection: bool,
    os_detection: bool,
    timing: Option<u8>,
    skip_discovery: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let cfg = build_config(
        &[target.to_string()],
        ports,
        scan_type,
        timeout,
        service_detection,
        os_detection,
        timing,
        skip_discovery,
    )?;

    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = rustmap_core::ScanEngine::run(&cfg)
            .await
            .map_err(|e| RustmapError::new_err(e.to_string()))?;
        Ok(PyScanResult::from_inner(result))
    })
}

/// Async scan with full config: `result = await rustmap.async_scan_with_config(config)`.
#[pyfunction]
fn async_scan_with_config<'py>(
    py: Python<'py>,
    config: &PyScanConfig,
) -> PyResult<Bound<'py, PyAny>> {
    let scan_config = config.to_scan_config()?;

    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let result = rustmap_core::ScanEngine::run(&scan_config)
            .await
            .map_err(|e| RustmapError::new_err(e.to_string()))?;
        Ok(PyScanResult::from_inner(result))
    })
}

/// Streaming scan: `async for event in rustmap.stream_scan(config)`.
///
/// The returned `ScanStream` has a `.cancel()` method that can be called to
/// abort the scan early.
#[pyfunction]
fn stream_scan(_py: Python<'_>, config: &PyScanConfig) -> PyResult<PyScanStream> {
    let scan_config = config.to_scan_config()?;
    let (tx, rx) = mpsc::channel(64);
    let cancel = rustmap_core::CancellationToken::new();
    let cancel_for_stream = cancel.clone();

    // Spawn the scan in a background tokio task.
    let rt = pyo3_async_runtimes::tokio::get_runtime();
    rt.spawn(async move {
        let _ = rustmap_core::ScanEngine::run_streaming(&scan_config, tx, cancel).await;
    });

    Ok(PyScanStream::new(rx, cancel_for_stream))
}

/// Parse a single target: `hosts = rustmap.parse_target("192.168.1.0/24")`.
#[pyfunction]
fn parse_target(input: &str) -> PyResult<Vec<host::PyHost>> {
    let hosts =
        rustmap_core::parse_target(input).map_err(|e| RustmapError::new_err(e.to_string()))?;
    Ok(hosts.into_iter().map(host::PyHost::from_inner).collect())
}

/// Parse multiple targets: `hosts = rustmap.parse_targets(["192.168.1.0/24", "10.0.0.1"])`.
#[pyfunction]
fn parse_targets(inputs: Vec<String>) -> PyResult<Vec<host::PyHost>> {
    let hosts = rustmap_core::parse_targets(&inputs)
        .map_err(|e| RustmapError::new_err(e.to_string()))?;
    Ok(hosts.into_iter().map(host::PyHost::from_inner).collect())
}

/// Build a ScanConfig from function arguments.
#[allow(clippy::too_many_arguments)]
fn build_config(
    targets: &[String],
    ports: Option<&str>,
    scan_type: Option<&str>,
    timeout: Option<f64>,
    service_detection: bool,
    os_detection: bool,
    timing: Option<u8>,
    skip_discovery: bool,
) -> PyResult<rustmap_types::ScanConfig> {
    let mut cfg = PyScanConfig::create();
    cfg.targets = targets.to_vec();
    if let Some(p) = ports {
        cfg.ports = Some(p.to_string());
    }
    if let Some(st) = scan_type {
        cfg.scan_type = st.to_string();
    }
    if let Some(t) = timeout {
        cfg.timeout_secs = t;
    }
    if let Some(t) = timing {
        cfg.timing = t;
    }
    cfg.service_detection = service_detection;
    cfg.os_detection = os_detection;
    cfg.skip_discovery = skip_discovery;
    cfg.to_scan_config()
}

/// Python module definition.
#[pymodule]
fn rustmap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<PyScanConfig>()?;
    m.add_class::<result::PyScanResult>()?;
    m.add_class::<result::PyHostScanResult>()?;
    m.add_class::<host::PyHost>()?;
    m.add_class::<host::PyGeoInfo>()?;
    m.add_class::<port::PyPort>()?;
    m.add_class::<port::PyServiceInfo>()?;
    m.add_class::<port::PyTlsFingerprint>()?;
    m.add_class::<port::PyCertificateInfo>()?;
    m.add_class::<os::PyOsFingerprint>()?;
    m.add_class::<timing::PyTimingSnapshot>()?;
    m.add_class::<traceroute::PyTracerouteResult>()?;
    m.add_class::<traceroute::PyTracerouteHop>()?;
    m.add_class::<script::PyScriptResult>()?;
    m.add_class::<PyScanStream>()?;

    // Functions
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(scan_with_config, m)?)?;
    m.add_function(wrap_pyfunction!(async_scan, m)?)?;
    m.add_function(wrap_pyfunction!(async_scan_with_config, m)?)?;
    m.add_function(wrap_pyfunction!(stream_scan, m)?)?;
    m.add_function(wrap_pyfunction!(parse_target, m)?)?;
    m.add_function(wrap_pyfunction!(parse_targets, m)?)?;

    // Exception
    m.add("RustmapError", m.py().get_type::<RustmapError>())?;

    // Version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
