use pyo3::prelude::*;
use rustmap_types::{GeoInfo, Host};

#[pyclass(name = "Host", frozen)]
pub struct PyHost {
    pub(crate) inner: Host,
}

#[pymethods]
impl PyHost {
    #[getter]
    fn ip(&self) -> String {
        self.inner.ip.to_string()
    }

    #[getter]
    fn hostname(&self) -> Option<String> {
        self.inner.hostname.clone()
    }

    #[getter]
    fn geo_info(&self) -> Option<PyGeoInfo> {
        self.inner.geo_info.clone().map(|g| PyGeoInfo { inner: g })
    }

    fn __repr__(&self) -> String {
        match &self.inner.hostname {
            Some(name) => format!("Host(ip='{}', hostname='{}')", self.inner.ip, name),
            None => format!("Host(ip='{}')", self.inner.ip),
        }
    }

    fn __str__(&self) -> String {
        self.inner.ip.to_string()
    }
}

impl PyHost {
    pub fn from_inner(inner: Host) -> Self {
        Self { inner }
    }
}

#[pyclass(name = "GeoInfo", frozen)]
pub struct PyGeoInfo {
    inner: GeoInfo,
}

#[pymethods]
impl PyGeoInfo {
    #[getter]
    fn country_code(&self) -> Option<String> {
        self.inner.country_code.clone()
    }
    #[getter]
    fn country(&self) -> Option<String> {
        self.inner.country.clone()
    }
    #[getter]
    fn city(&self) -> Option<String> {
        self.inner.city.clone()
    }
    #[getter]
    fn latitude(&self) -> Option<f64> {
        self.inner.latitude
    }
    #[getter]
    fn longitude(&self) -> Option<f64> {
        self.inner.longitude
    }
    #[getter]
    fn timezone(&self) -> Option<String> {
        self.inner.timezone.clone()
    }
    #[getter]
    fn asn(&self) -> Option<u32> {
        self.inner.asn
    }
    #[getter]
    fn as_org(&self) -> Option<String> {
        self.inner.as_org.clone()
    }

    fn __repr__(&self) -> String {
        let parts: Vec<String> = [
            self.inner.country.as_deref().map(|s| s.to_string()),
            self.inner.city.as_deref().map(|s| s.to_string()),
            self.inner.as_org.as_deref().map(|_| format!("AS{}", self.inner.asn.unwrap_or(0))),
        ]
        .into_iter()
        .flatten()
        .collect();
        format!("GeoInfo({})", parts.join(", "))
    }
}
