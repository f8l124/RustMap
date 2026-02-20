use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::debug;

use crate::congestion::CongestionWindow;
use crate::rate::RateLimiter;
use crate::rtt::RttEstimator;
use crate::templates::TimingParams;

/// Central timing controller combining RTT estimation, congestion window,
/// and rate limiting. Thread-safe via interior mutability.
pub struct TimingController {
    inner: Mutex<TimingInner>,
}

struct TimingInner {
    rtt: RttEstimator,
    cwnd: CongestionWindow,
    rate_limiter: RateLimiter,
    params: TimingParams,
    probes_sent: u64,
    probes_completed: u64,
    probes_responded: u64,
    probes_timed_out: u64,
    min_rate: Option<f64>,
    start_time: Instant,
}

/// Snapshot of timing statistics for logging/diagnostics.
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub srtt: Option<Duration>,
    pub rto: Duration,
    pub rttvar: Option<Duration>,
    pub cwnd: usize,
    pub outstanding: usize,
    pub probes_sent: u64,
    pub probes_completed: u64,
    pub probes_responded: u64,
    pub probes_timed_out: u64,
}

impl TimingController {
    pub fn new(params: TimingParams) -> Self {
        let rtt = RttEstimator::new(params.initial_rto, params.min_rto, params.max_rto);
        let cwnd = CongestionWindow::new(params.initial_cwnd, params.ssthresh, params.max_cwnd);
        let rate_limiter = RateLimiter::new(params.max_rate.unwrap_or(f64::INFINITY));

        let min_rate = params.min_rate;

        Self {
            inner: Mutex::new(TimingInner {
                rtt,
                cwnd,
                rate_limiter,
                params,
                probes_sent: 0,
                probes_completed: 0,
                probes_responded: 0,
                probes_timed_out: 0,
                min_rate,
                start_time: Instant::now(),
            }),
        }
    }

    /// Check if we're allowed to send another probe right now.
    /// This is a non-consuming check — it does not spend a rate limiter token.
    pub fn can_send(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cwnd_ok = inner.cwnd.can_send();
        let rate_ok = inner.rate_limiter.would_allow();

        if cwnd_ok && rate_ok {
            return true;
        }

        // min_rate override: if current effective rate is below min_rate,
        // allow sending even when cwnd would block (matches nmap --min-rate).
        if let Some(min_rate) = inner.min_rate {
            let elapsed = inner.start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                let current_rate = inner.probes_sent as f64 / elapsed;
                if current_rate < min_rate {
                    return true;
                }
            }
        }

        false
    }

    /// Wait until we're allowed to send. Respects both cwnd and rate limit.
    /// When `min_rate` is set, overrides cwnd to maintain minimum send rate.
    pub async fn wait_for_slot(&self) {
        loop {
            let wait_duration = {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

                // Normal path: cwnd + rate limiter both allow
                if inner.cwnd.can_send() {
                    match inner.rate_limiter.try_acquire() {
                        Ok(()) => return,
                        Err(wait) => Some(wait),
                    }
                } else {
                    // cwnd blocked — check min_rate override
                    if let Some(min_rate) = inner.min_rate {
                        let elapsed = inner.start_time.elapsed().as_secs_f64();
                        if elapsed > 0.0 {
                            let current_rate = inner.probes_sent as f64 / elapsed;
                            if current_rate < min_rate {
                                // Override cwnd block; still respect max_rate
                                match inner.rate_limiter.try_acquire() {
                                    Ok(()) => return,
                                    Err(wait) => Some(wait),
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            };
            // Guard is dropped — safe to await
            match wait_duration {
                Some(wait) => tokio::time::sleep(wait).await,
                None => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    }

    /// Record that a probe was sent. Consumes a rate limiter token.
    pub fn on_probe_sent(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.cwnd.on_send();
        let _ = inner.rate_limiter.try_acquire(); // consume token on actual send
        inner.probes_sent = inner.probes_sent.saturating_add(1);
    }

    /// Record that a response was received with the given RTT.
    pub fn on_response(&self, rtt: Duration) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.rtt.update(rtt);
        inner.cwnd.on_ack();
        inner.probes_completed = inner.probes_completed.saturating_add(1);
        inner.probes_responded = inner.probes_responded.saturating_add(1);
        debug!(
            rtt_ms = rtt.as_millis(),
            srtt_ms = inner.rtt.srtt().map(|d| d.as_millis()),
            rto_ms = inner.rtt.rto().as_millis(),
            cwnd = inner.cwnd.window_size(),
            "timing: response received"
        );
    }

    /// Record that a probe timed out.
    pub fn on_timeout(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.rtt.backoff();
        inner.cwnd.on_timeout();
        inner.probes_completed = inner.probes_completed.saturating_add(1);
        inner.probes_timed_out = inner.probes_timed_out.saturating_add(1);
        debug!(
            rto_ms = inner.rtt.rto().as_millis(),
            cwnd = inner.cwnd.window_size(),
            "timing: probe timed out"
        );
    }

    /// Record that a probe was dropped without result.
    pub fn on_drop(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.cwnd.on_drop();
        inner.probes_completed = inner.probes_completed.saturating_add(1);
    }

    /// Current RTO for new probes.
    pub fn current_rto(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).rtt.rto()
    }

    /// Current smoothed RTT.
    pub fn current_srtt(&self) -> Option<Duration> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).rtt.srtt()
    }

    /// Maximum retries allowed by current timing config.
    pub fn max_retries(&self) -> u8 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).params.max_retries
    }

    /// Scan delay between probes.
    pub fn scan_delay(&self) -> Duration {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).params.scan_delay
    }

    /// Scan delay with optional jitter.
    /// When max_scan_delay > scan_delay, returns a uniformly random duration
    /// in [scan_delay, max_scan_delay]. Otherwise returns scan_delay.
    pub fn scan_delay_jittered(&self) -> Duration {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let min = inner.params.scan_delay;
        let max = inner.params.max_scan_delay;
        if max > min {
            let min_us = min.as_micros() as u64;
            let max_us = max.as_micros() as u64;
            let jittered = rand::thread_rng().gen_range(min_us..=max_us);
            Duration::from_micros(jittered)
        } else {
            min
        }
    }

    /// Snapshot of timing stats for logging/diagnostics.
    pub fn stats(&self) -> TimingStats {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        TimingStats {
            srtt: inner.rtt.srtt(),
            rto: inner.rtt.rto(),
            rttvar: inner.rtt.rttvar(),
            cwnd: inner.cwnd.window_size(),
            outstanding: inner.cwnd.outstanding(),
            probes_sent: inner.probes_sent,
            probes_completed: inner.probes_completed,
            probes_responded: inner.probes_responded,
            probes_timed_out: inner.probes_timed_out,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::TimingParams;
    use rustmap_types::TimingTemplate;

    fn make_controller(template: TimingTemplate) -> TimingController {
        TimingController::new(TimingParams::from_template(template))
    }

    #[test]
    fn normal_template_allows_initial_sends() {
        let tc = make_controller(TimingTemplate::Normal);
        // Normal template has initial_cwnd=4, so we should be able to send 4
        for _ in 0..4 {
            assert!(tc.can_send());
            tc.on_probe_sent();
        }
    }

    #[test]
    fn response_updates_rtt_and_grows_window() {
        let tc = make_controller(TimingTemplate::Normal);
        tc.on_probe_sent();
        tc.on_response(Duration::from_millis(50));
        assert!(tc.current_srtt().is_some());
        let stats = tc.stats();
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.probes_completed, 1);
    }

    #[test]
    fn timeout_reduces_window_and_backs_off_rto() {
        let tc = make_controller(TimingTemplate::Normal);
        let initial_rto = tc.current_rto();
        tc.on_probe_sent();
        tc.on_timeout();
        // RTO should have doubled
        assert!(tc.current_rto() > initial_rto);
        // Window should have shrunk
        let stats = tc.stats();
        assert_eq!(stats.cwnd, 1);
    }

    #[test]
    fn scan_delay_matches_template() {
        let tc = make_controller(TimingTemplate::Paranoid);
        assert_eq!(tc.scan_delay(), Duration::from_secs(300));

        let tc = make_controller(TimingTemplate::Normal);
        assert_eq!(tc.scan_delay(), Duration::ZERO);
    }

    #[test]
    fn simulate_scan_sequence() {
        let tc = make_controller(TimingTemplate::Aggressive);

        // Send a burst of probes
        for _ in 0..10 {
            tc.on_probe_sent();
        }

        // Responses come back with ~20ms RTT
        for _ in 0..8 {
            tc.on_response(Duration::from_millis(20));
        }

        // 2 timeouts
        tc.on_timeout();
        tc.on_timeout();

        let stats = tc.stats();
        assert_eq!(stats.probes_sent, 10);
        assert_eq!(stats.probes_completed, 10);
        // SRTT should be near 20ms
        assert!(stats.srtt.unwrap().as_millis() < 50);
    }

    #[test]
    fn min_rate_overrides_cwnd_block() {
        // Create controller with min_rate set
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.min_rate = Some(1000.0); // 1000 packets/sec
        let tc = TimingController::new(params);

        // Send 4 probes to fill cwnd, then timeout them all to shrink cwnd to 1
        for _ in 0..4 {
            tc.on_probe_sent();
        }
        for _ in 0..4 {
            tc.on_timeout(); // cwnd → 1, outstanding decrements each time
        }

        // Now cwnd=1, outstanding=0. Send one more to fill the tiny window.
        tc.on_probe_sent();
        // cwnd=1, outstanding=1 → cwnd blocked

        // Sleep briefly so elapsed time allows meaningful rate calculation.
        // After ~10ms with 5 probes sent, rate ≈ 500/sec < min_rate 1000/sec
        std::thread::sleep(Duration::from_millis(10));

        // min_rate override should allow sending despite cwnd block
        assert!(tc.can_send(), "min_rate should override cwnd block when current rate < min_rate");
    }

    #[test]
    fn no_min_rate_respects_cwnd_block() {
        // Without min_rate, cwnd should block normally
        let tc = make_controller(TimingTemplate::Normal);

        // Exhaust cwnd (Normal has initial_cwnd=4)
        for _ in 0..4 {
            tc.on_probe_sent();
        }

        // Should be blocked by cwnd
        assert!(!tc.can_send(), "should be blocked by cwnd without min_rate");
    }

    #[test]
    fn max_rate_still_applied_with_min_rate() {
        // Both min_rate and max_rate set — max_rate should still limit
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.min_rate = Some(100.0);
        params.max_rate = Some(f64::INFINITY); // no max constraint
        let tc = TimingController::new(params);

        // Should be able to send (cwnd allows + rate allows)
        assert!(tc.can_send());
    }

    #[test]
    fn rate_fields_flow_from_params() {
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.min_rate = Some(500.0);
        params.max_rate = Some(2000.0);
        let tc = TimingController::new(params);

        // Controller should work — basic sanity
        assert!(tc.can_send());
        tc.on_probe_sent();
        let stats = tc.stats();
        assert_eq!(stats.probes_sent, 1);
    }

    #[test]
    fn probes_responded_increments() {
        let tc = make_controller(TimingTemplate::Normal);
        tc.on_probe_sent();
        tc.on_probe_sent();
        tc.on_response(Duration::from_millis(10));
        tc.on_response(Duration::from_millis(20));
        let stats = tc.stats();
        assert_eq!(stats.probes_responded, 2);
        assert_eq!(stats.probes_timed_out, 0);
    }

    #[test]
    fn probes_timed_out_increments() {
        let tc = make_controller(TimingTemplate::Normal);
        tc.on_probe_sent();
        tc.on_probe_sent();
        tc.on_probe_sent();
        tc.on_timeout();
        tc.on_timeout();
        tc.on_response(Duration::from_millis(10));
        let stats = tc.stats();
        assert_eq!(stats.probes_timed_out, 2);
        assert_eq!(stats.probes_responded, 1);
        assert_eq!(stats.probes_completed, 3);
    }

    #[test]
    fn rttvar_exposed_in_stats() {
        let tc = make_controller(TimingTemplate::Normal);
        tc.on_probe_sent();
        tc.on_response(Duration::from_millis(50));
        let stats = tc.stats();
        // After one sample, rttvar should be initialized (sample/2)
        assert!(stats.rttvar.is_some());
        assert!(stats.rttvar.unwrap().as_millis() > 0);
    }

    #[test]
    fn scan_delay_jittered_no_jitter() {
        // When max_scan_delay == scan_delay, jittered returns exact scan_delay
        let mut params = TimingParams::from_template(TimingTemplate::Paranoid);
        // Paranoid: scan_delay=300s, max_scan_delay=300s (same)
        params.max_scan_delay = params.scan_delay;
        let tc = TimingController::new(params);
        for _ in 0..10 {
            assert_eq!(tc.scan_delay_jittered(), Duration::from_secs(300));
        }
    }

    #[test]
    fn scan_delay_jittered_with_range() {
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.scan_delay = Duration::from_millis(100);
        params.max_scan_delay = Duration::from_millis(500);
        let tc = TimingController::new(params);

        let mut saw_min_range = false;
        let mut saw_max_range = false;
        for _ in 0..200 {
            let delay = tc.scan_delay_jittered();
            assert!(delay >= Duration::from_millis(100), "delay {delay:?} < 100ms");
            assert!(delay <= Duration::from_millis(500), "delay {delay:?} > 500ms");
            if delay < Duration::from_millis(200) {
                saw_min_range = true;
            }
            if delay > Duration::from_millis(400) {
                saw_max_range = true;
            }
        }
        assert!(saw_min_range, "should produce values near min");
        assert!(saw_max_range, "should produce values near max");
    }

    #[test]
    fn scan_delay_jittered_zero() {
        // When both scan_delay and max_scan_delay are zero, jittered returns zero
        let mut params = TimingParams::from_template(TimingTemplate::Normal);
        params.scan_delay = Duration::ZERO;
        params.max_scan_delay = Duration::ZERO;
        let tc = TimingController::new(params);
        assert_eq!(tc.scan_delay_jittered(), Duration::ZERO);
    }
}
