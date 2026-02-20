use rustmap_types::TimingTemplate;
use std::time::Duration;

/// All timing parameters derived from a template.
#[derive(Debug, Clone)]
pub struct TimingParams {
    pub initial_rto: Duration,
    pub min_rto: Duration,
    pub max_rto: Duration,
    pub initial_cwnd: f64,
    pub max_cwnd: f64,
    pub ssthresh: f64,
    pub max_retries: u8,
    pub host_timeout: Duration,
    pub scan_delay: Duration,
    /// Upper bound for dynamic scan delay growth (not yet used; reserved for
    /// future adaptive inter-probe delay, matching nmap's --max-scan-delay).
    pub max_scan_delay: Duration,
    pub min_rate: Option<f64>,
    pub max_rate: Option<f64>,
    /// Default concurrent TCP connect() calls for this timing template.
    pub connect_concurrency: usize,
    /// Default per-connection timeout for TCP connect() scans.
    pub connect_timeout: Duration,
}

impl TimingParams {
    /// Build parameters from a timing template.
    pub fn from_template(template: TimingTemplate) -> Self {
        match template {
            TimingTemplate::Paranoid => Self {
                initial_rto: Duration::from_secs(15),
                min_rto: Duration::from_millis(500),
                max_rto: Duration::from_secs(30),
                initial_cwnd: 1.0,
                max_cwnd: 2.0,
                ssthresh: 2.0,
                max_retries: 10,
                host_timeout: Duration::ZERO, // no host timeout
                scan_delay: Duration::from_secs(300), // 5 minutes
                max_scan_delay: Duration::from_secs(300),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 1,
                connect_timeout: Duration::from_secs(15),
            },
            TimingTemplate::Sneaky => Self {
                initial_rto: Duration::from_secs(15),
                min_rto: Duration::from_millis(500),
                max_rto: Duration::from_secs(30),
                initial_cwnd: 1.0,
                max_cwnd: 2.0,
                ssthresh: 2.0,
                max_retries: 10,
                host_timeout: Duration::ZERO,
                scan_delay: Duration::from_secs(15),
                max_scan_delay: Duration::from_secs(15),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 5,
                connect_timeout: Duration::from_secs(15),
            },
            TimingTemplate::Polite => Self {
                initial_rto: Duration::from_secs(1),
                min_rto: Duration::from_millis(250),
                max_rto: Duration::from_secs(10),
                initial_cwnd: 1.0,
                max_cwnd: 10.0,
                ssthresh: 10.0,
                max_retries: 10,
                host_timeout: Duration::ZERO,
                scan_delay: Duration::from_millis(400),
                max_scan_delay: Duration::from_secs(1),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 10,
                connect_timeout: Duration::from_secs(3),
            },
            TimingTemplate::Normal => Self {
                initial_rto: Duration::from_secs(1),
                min_rto: Duration::from_millis(100),
                max_rto: Duration::from_secs(10),
                initial_cwnd: 4.0,
                max_cwnd: 300.0,
                ssthresh: 64.0,
                max_retries: 3,
                host_timeout: Duration::ZERO,
                scan_delay: Duration::ZERO,
                max_scan_delay: Duration::from_secs(1),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 1000,
                connect_timeout: Duration::from_millis(1500),
            },
            TimingTemplate::Aggressive => Self {
                initial_rto: Duration::from_millis(500),
                min_rto: Duration::from_millis(100),
                max_rto: Duration::from_millis(1250),
                initial_cwnd: 10.0,
                max_cwnd: 300.0,
                ssthresh: 64.0,
                max_retries: 6,
                host_timeout: Duration::from_secs(600), // 10 minutes
                scan_delay: Duration::from_millis(10),
                max_scan_delay: Duration::from_millis(10),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 3000,
                connect_timeout: Duration::from_millis(1000),
            },
            TimingTemplate::Insane => Self {
                initial_rto: Duration::from_millis(250),
                min_rto: Duration::from_millis(50),
                max_rto: Duration::from_millis(300),
                initial_cwnd: 300.0,
                max_cwnd: 10000.0,
                ssthresh: 256.0,
                max_retries: 2,
                host_timeout: Duration::from_secs(300), // 5 minutes
                scan_delay: Duration::ZERO,
                max_scan_delay: Duration::from_millis(5),
                min_rate: None,
                max_rate: None,
                connect_concurrency: 5000,
                connect_timeout: Duration::from_millis(500),
            },
        }
    }

    /// Apply learned overrides from historical data, clamped to template bounds.
    pub fn apply_learned(
        &mut self,
        initial_rto_us: Option<u64>,
        cwnd: Option<f64>,
        ssthresh: Option<f64>,
        max_retries: Option<u8>,
    ) {
        if let Some(rto) = initial_rto_us {
            let rto_dur = Duration::from_micros(rto);
            self.initial_rto = rto_dur.clamp(self.min_rto, self.max_rto);
        }
        if let Some(c) = cwnd
            && c.is_finite()
        {
            self.initial_cwnd = c.clamp(1.0, self.max_cwnd);
        }
        if let Some(ss) = ssthresh
            && ss.is_finite()
        {
            self.ssthresh = ss.clamp(1.0, self.max_cwnd);
        }
        if let Some(r) = max_retries {
            // Clamp to [0, 10] — template max is 10 (Paranoid/Sneaky/Polite)
            self.max_retries = r.min(10);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_templates_produce_valid_params() {
        let templates = [
            TimingTemplate::Paranoid,
            TimingTemplate::Sneaky,
            TimingTemplate::Polite,
            TimingTemplate::Normal,
            TimingTemplate::Aggressive,
            TimingTemplate::Insane,
        ];

        for template in templates {
            let params = TimingParams::from_template(template);
            assert!(params.min_rto <= params.initial_rto, "{template:?}: min_rto > initial_rto");
            assert!(params.initial_rto <= params.max_rto, "{template:?}: initial_rto > max_rto");
            assert!(params.initial_cwnd >= 1.0, "{template:?}: initial_cwnd < 1");
            assert!(params.initial_cwnd <= params.max_cwnd, "{template:?}: initial_cwnd > max_cwnd");
            assert!(params.connect_concurrency >= 1, "{template:?}: connect_concurrency < 1");
            assert!(
                params.connect_timeout > Duration::ZERO,
                "{template:?}: connect_timeout is zero"
            );
        }
    }

    #[test]
    fn connect_params_scale_with_aggressiveness() {
        let normal = TimingParams::from_template(TimingTemplate::Normal);
        let aggressive = TimingParams::from_template(TimingTemplate::Aggressive);
        let insane = TimingParams::from_template(TimingTemplate::Insane);

        assert!(aggressive.connect_concurrency > normal.connect_concurrency);
        assert!(insane.connect_concurrency > aggressive.connect_concurrency);
        assert!(aggressive.connect_timeout < normal.connect_timeout);
        assert!(insane.connect_timeout < aggressive.connect_timeout);
    }

    #[test]
    fn default_is_normal() {
        assert_eq!(TimingTemplate::default(), TimingTemplate::Normal);
    }

    #[test]
    fn paranoid_is_slowest() {
        let paranoid = TimingParams::from_template(TimingTemplate::Paranoid);
        let normal = TimingParams::from_template(TimingTemplate::Normal);
        assert!(paranoid.scan_delay > normal.scan_delay);
        assert!(paranoid.initial_rto >= normal.initial_rto);
    }

    #[test]
    fn insane_is_fastest() {
        let insane = TimingParams::from_template(TimingTemplate::Insane);
        let normal = TimingParams::from_template(TimingTemplate::Normal);
        assert!(insane.initial_rto < normal.initial_rto);
        assert!(insane.initial_cwnd > normal.initial_cwnd);
        assert!(insane.max_retries < normal.max_retries);
    }

    #[test]
    fn apply_learned_clamps_to_bounds() {
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        // Try to set RTO below min_rto (100ms for Normal)
        params.apply_learned(Some(1000), None, None, None); // 1ms < 100ms
        assert_eq!(params.initial_rto, params.min_rto);

        // Try to set cwnd above max_cwnd
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.apply_learned(None, Some(999.0), None, None);
        assert_eq!(params.initial_cwnd, params.max_cwnd); // Normal max_cwnd=300
    }

    #[test]
    fn apply_learned_none_preserves_template() {
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        let original_rto = params.initial_rto;
        let original_cwnd = params.initial_cwnd;
        params.apply_learned(None, None, None, None);
        assert_eq!(params.initial_rto, original_rto);
        assert_eq!(params.initial_cwnd, original_cwnd);
    }

    #[test]
    fn apply_learned_valid_values() {
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        // Set RTO to 500ms (within Normal bounds: 100ms-10s)
        params.apply_learned(Some(500_000), Some(10.0), Some(32.0), Some(2));
        assert_eq!(params.initial_rto, Duration::from_millis(500));
        assert_eq!(params.initial_cwnd, 10.0);
        assert_eq!(params.ssthresh, 32.0);
        assert_eq!(params.max_retries, 2);
    }
}
