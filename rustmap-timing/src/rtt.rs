use std::time::Duration;

/// Jacobson/Karels RTT estimator (RFC 6298).
///
/// Maintains smoothed RTT (SRTT) and RTT variance (RTTVAR) to compute
/// a retransmission timeout (RTO) that adapts to network conditions.
///
/// Formulas:
///   SRTT    = SRTT + (sample - SRTT) / 8
///   RTTVAR  = RTTVAR + (|sample - SRTT| - RTTVAR) / 4
///   RTO     = SRTT + max(G, 4 * RTTVAR)
#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Option<Duration>,
    rto: Duration,
    min_rto: Duration,
    max_rto: Duration,
    clock_granularity: Duration,
}

impl RttEstimator {
    pub fn new(initial_rto: Duration, min_rto: Duration, max_rto: Duration) -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: initial_rto,
            min_rto,
            max_rto,
            clock_granularity: Duration::from_millis(1),
        }
    }

    /// Feed a new RTT sample and update SRTT, RTTVAR, RTO.
    pub fn update(&mut self, sample: Duration) {
        let sample_us = sample.as_micros() as f64;

        match self.srtt {
            None => {
                // First measurement (RFC 6298 Section 2.2)
                self.srtt = Some(sample);
                self.rttvar = Some(sample / 2);
            }
            Some(srtt) => {
                let srtt_us = srtt.as_micros() as f64;
                let rttvar_us = self.rttvar.unwrap().as_micros() as f64;

                // RTTVAR = (1 - 1/4) * RTTVAR + 1/4 * |SRTT - sample|
                let diff = (srtt_us - sample_us).abs();
                let new_rttvar = rttvar_us + (diff - rttvar_us) / 4.0;

                // SRTT = (1 - 1/8) * SRTT + 1/8 * sample
                let new_srtt = srtt_us + (sample_us - srtt_us) / 8.0;

                self.srtt = Some(Duration::from_micros(new_srtt.max(1.0) as u64));
                self.rttvar = Some(Duration::from_micros(new_rttvar.max(1.0) as u64));
            }
        }

        self.recalc_rto();
    }

    /// Current retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Current smoothed RTT, if any samples have been recorded.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Current RTT variance, if any samples have been recorded.
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// Double the RTO for exponential backoff (called on timeout).
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(self.max_rto);
    }

    /// Reset to initial state with a new initial RTO.
    pub fn reset(&mut self, initial_rto: Duration) {
        self.srtt = None;
        self.rttvar = None;
        self.rto = initial_rto;
    }

    fn recalc_rto(&mut self) {
        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            // RTO = SRTT + max(G, 4 * RTTVAR)
            let k_rttvar = rttvar * 4;
            let variance_term = k_rttvar.max(self.clock_granularity);
            self.rto = (srtt + variance_term).clamp(self.min_rto, self.max_rto);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_initializes_srtt() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );
        assert!(rtt.srtt().is_none());
        rtt.update(Duration::from_millis(50));
        assert_eq!(rtt.srtt(), Some(Duration::from_millis(50)));
        // RTTVAR = sample / 2
        assert_eq!(rtt.rttvar(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn rto_converges_with_stable_rtt() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_secs(10),
        );
        // Feed 20 identical samples
        for _ in 0..20 {
            rtt.update(Duration::from_millis(100));
        }
        // SRTT should converge near 100ms
        let srtt = rtt.srtt().unwrap();
        assert!(srtt.as_millis() >= 95 && srtt.as_millis() <= 105);
        // RTTVAR should shrink toward 0, so RTO should be close to SRTT + G
        assert!(rtt.rto().as_millis() < 200);
    }

    #[test]
    fn backoff_doubles_rto() {
        let mut rtt = RttEstimator::new(
            Duration::from_millis(500),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );
        assert_eq!(rtt.rto(), Duration::from_millis(500));
        rtt.backoff();
        assert_eq!(rtt.rto(), Duration::from_secs(1));
        rtt.backoff();
        assert_eq!(rtt.rto(), Duration::from_secs(2));
    }

    #[test]
    fn backoff_respects_max_rto() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(5),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );
        rtt.backoff(); // 10s
        rtt.backoff(); // capped at 10s
        assert_eq!(rtt.rto(), Duration::from_secs(10));
    }

    #[test]
    fn rto_respects_min_rto() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );
        // Very fast RTT
        for _ in 0..20 {
            rtt.update(Duration::from_micros(500));
        }
        assert!(rtt.rto() >= Duration::from_millis(100));
    }

    #[test]
    fn reset_clears_state() {
        let mut rtt = RttEstimator::new(
            Duration::from_secs(1),
            Duration::from_millis(100),
            Duration::from_secs(10),
        );
        rtt.update(Duration::from_millis(50));
        assert!(rtt.srtt().is_some());
        rtt.reset(Duration::from_secs(2));
        assert!(rtt.srtt().is_none());
        assert_eq!(rtt.rto(), Duration::from_secs(2));
    }
}
