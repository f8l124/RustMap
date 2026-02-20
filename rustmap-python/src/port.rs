use pyo3::prelude::*;
use rustmap_types::{CertificateInfo, Port, ServiceInfo, TlsServerFingerprint};

use crate::enums::{detection_method_to_str, port_state_to_str, protocol_to_str};
use crate::script::PyScriptResult;

#[pyclass(name = "Port", frozen)]
pub struct PyPort {
    pub(crate) inner: Port,
}

#[pymethods]
impl PyPort {
    #[getter]
    fn number(&self) -> u16 {
        self.inner.number
    }
    #[getter]
    fn protocol(&self) -> String {
        protocol_to_str(self.inner.protocol).to_string()
    }
    #[getter]
    fn state(&self) -> String {
        port_state_to_str(self.inner.state).to_string()
    }
    #[getter]
    fn service(&self) -> Option<String> {
        self.inner.service.clone()
    }
    #[getter]
    fn service_info(&self) -> Option<PyServiceInfo> {
        self.inner
            .service_info
            .clone()
            .map(|si| PyServiceInfo { inner: si })
    }
    #[getter]
    fn reason(&self) -> Option<String> {
        self.inner.reason.clone()
    }
    #[getter]
    fn script_results(&self) -> Vec<PyScriptResult> {
        self.inner
            .script_results
            .iter()
            .map(|sr| PyScriptResult::from_inner(sr.clone()))
            .collect()
    }
    #[getter]
    fn tls_info(&self) -> Option<PyTlsFingerprint> {
        self.inner
            .tls_info
            .clone()
            .map(|tls| PyTlsFingerprint { inner: tls })
    }

    fn __repr__(&self) -> String {
        format!(
            "Port({}/{} {} {})",
            self.inner.number,
            protocol_to_str(self.inner.protocol),
            port_state_to_str(self.inner.state),
            self.inner.service.as_deref().unwrap_or("")
        )
    }
}

impl PyPort {
    pub fn from_inner(inner: Port) -> Self {
        Self { inner }
    }
}

#[pyclass(name = "ServiceInfo", frozen)]
pub struct PyServiceInfo {
    inner: ServiceInfo,
}

#[pymethods]
impl PyServiceInfo {
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }
    #[getter]
    fn product(&self) -> Option<String> {
        self.inner.product.clone()
    }
    #[getter]
    fn version(&self) -> Option<String> {
        self.inner.version.clone()
    }
    #[getter]
    fn info(&self) -> Option<String> {
        self.inner.info.clone()
    }
    #[getter]
    fn method(&self) -> String {
        detection_method_to_str(self.inner.method).to_string()
    }

    fn version_display(&self) -> Option<String> {
        self.inner.version_display()
    }

    fn __repr__(&self) -> String {
        let version = self.inner.version_display().unwrap_or_default();
        format!("ServiceInfo(name='{}', version='{}')", self.inner.name, version)
    }
}

#[pyclass(name = "TlsFingerprint", frozen)]
pub struct PyTlsFingerprint {
    inner: TlsServerFingerprint,
}

#[pymethods]
impl PyTlsFingerprint {
    #[getter]
    fn tls_version(&self) -> u16 {
        self.inner.tls_version
    }
    #[getter]
    fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite
    }
    #[getter]
    fn extensions(&self) -> Vec<u16> {
        self.inner.extensions.clone()
    }
    #[getter]
    fn compression_method(&self) -> u8 {
        self.inner.compression_method
    }
    #[getter]
    fn alpn(&self) -> Option<String> {
        self.inner.alpn.clone()
    }
    #[getter]
    fn ja4s(&self) -> Option<String> {
        self.inner.ja4s.clone()
    }
    #[getter]
    fn sni(&self) -> Option<String> {
        self.inner.sni.clone()
    }
    #[getter]
    fn certificate_chain(&self) -> Option<Vec<PyCertificateInfo>> {
        self.inner
            .certificate_chain
            .clone()
            .map(|chain| chain.into_iter().map(|c| PyCertificateInfo { inner: c }).collect())
    }

    fn __repr__(&self) -> String {
        let ver = match self.inner.tls_version {
            0x0304 => "1.3",
            0x0303 => "1.2",
            0x0302 => "1.1",
            0x0301 => "1.0",
            _ => "unknown",
        };
        format!("TlsFingerprint(version='{}', alpn={:?})", ver, self.inner.alpn)
    }
}

#[pyclass(name = "CertificateInfo", frozen)]
pub struct PyCertificateInfo {
    inner: CertificateInfo,
}

#[pymethods]
impl PyCertificateInfo {
    #[getter]
    fn subject_cn(&self) -> Option<String> {
        self.inner.subject_cn.clone()
    }
    #[getter]
    fn subject_dn(&self) -> Option<String> {
        self.inner.subject_dn.clone()
    }
    #[getter]
    fn issuer_cn(&self) -> Option<String> {
        self.inner.issuer_cn.clone()
    }
    #[getter]
    fn issuer_dn(&self) -> Option<String> {
        self.inner.issuer_dn.clone()
    }
    #[getter]
    fn serial(&self) -> Option<String> {
        self.inner.serial.clone()
    }
    #[getter]
    fn not_before(&self) -> Option<String> {
        self.inner.not_before.clone()
    }
    #[getter]
    fn not_after(&self) -> Option<String> {
        self.inner.not_after.clone()
    }
    #[getter]
    fn san_dns(&self) -> Vec<String> {
        self.inner.san_dns.clone()
    }
    #[getter]
    fn signature_algorithm(&self) -> Option<String> {
        self.inner.signature_algorithm.clone()
    }
    #[getter]
    fn public_key_info(&self) -> Option<String> {
        self.inner.public_key_info.clone()
    }
    #[getter]
    fn sha256_fingerprint(&self) -> Option<String> {
        self.inner.sha256_fingerprint.clone()
    }
    #[getter]
    fn self_signed(&self) -> bool {
        self.inner.self_signed
    }
    #[getter]
    fn chain_position(&self) -> u8 {
        self.inner.chain_position
    }

    fn __repr__(&self) -> String {
        let cn = self.inner.subject_cn.as_deref().unwrap_or("unknown");
        let pos = self.inner.chain_position;
        format!("CertificateInfo(cn='{cn}', position={pos})")
    }
}
