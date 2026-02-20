/// TCP-like congestion window for controlling outstanding probe count.
///
/// Uses slow-start (exponential growth) when cwnd < ssthresh,
/// then switches to congestion avoidance (linear growth).
///
/// On timeout (loss signal): ssthresh = cwnd / 2, cwnd = min_cwnd.
#[derive(Debug, Clone)]
pub struct CongestionWindow {
    cwnd: f64,
    ssthresh: f64,
    min_cwnd: f64,
    max_cwnd: f64,
    outstanding: usize,
}

impl CongestionWindow {
    pub fn new(initial_cwnd: f64, ssthresh: f64, max_cwnd: f64) -> Self {
        // Clamp to sane bounds — min_cwnd is always 1.0
        let max_cwnd = if max_cwnd.is_finite() && max_cwnd >= 1.0 {
            max_cwnd
        } else {
            300.0 // safe default
        };
        let initial_cwnd = if initial_cwnd.is_finite() && initial_cwnd >= 1.0 {
            initial_cwnd.min(max_cwnd)
        } else {
            1.0
        };
        let ssthresh = if ssthresh.is_finite() && ssthresh >= 1.0 {
            ssthresh
        } else {
            64.0 // safe default
        };
        Self {
            cwnd: initial_cwnd,
            ssthresh,
            min_cwnd: 1.0,
            max_cwnd,
            outstanding: 0,
        }
    }

    /// Can we send another probe? (outstanding < floor(cwnd))
    pub fn can_send(&self) -> bool {
        self.outstanding < self.cwnd.floor() as usize
    }

    /// Number of additional probes we can send right now.
    pub fn available_slots(&self) -> usize {
        let max = self.cwnd.floor() as usize;
        max.saturating_sub(self.outstanding)
    }

    /// Mark a probe as sent (increments outstanding count).
    pub fn on_send(&mut self) {
        self.outstanding += 1;
    }

    /// A probe was acknowledged (response received).
    /// Grows cwnd: +1 per ACK in slow-start, +1/cwnd per ACK in congestion avoidance.
    pub fn on_ack(&mut self) {
        self.outstanding = self.outstanding.saturating_sub(1);

        if self.cwnd < self.ssthresh {
            // Slow start: exponential growth (add 1 per ACK)
            self.cwnd += 1.0;
        } else {
            // Congestion avoidance: linear growth (add 1/cwnd per ACK)
            self.cwnd += 1.0 / self.cwnd;
        }

        self.cwnd = self.cwnd.min(self.max_cwnd);
    }

    /// A probe timed out (congestion signal).
    /// Sets ssthresh = cwnd / 2, resets cwnd to min.
    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(self.min_cwnd);
        self.cwnd = self.min_cwnd;
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    /// A probe was dropped/cancelled without result.
    pub fn on_drop(&mut self) {
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    /// Current window size (floored to integer).
    pub fn window_size(&self) -> usize {
        self.cwnd.floor() as usize
    }

    /// Current number of outstanding probes.
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// Current slow-start threshold.
    pub fn ssthresh(&self) -> f64 {
        self.ssthresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let cwnd = CongestionWindow::new(4.0, 64.0, 300.0);
        assert_eq!(cwnd.window_size(), 4);
        assert_eq!(cwnd.outstanding(), 0);
        assert!(cwnd.can_send());
        assert_eq!(cwnd.available_slots(), 4);
    }

    #[test]
    fn send_decrements_available() {
        let mut cwnd = CongestionWindow::new(4.0, 64.0, 300.0);
        cwnd.on_send();
        cwnd.on_send();
        assert_eq!(cwnd.outstanding(), 2);
        assert_eq!(cwnd.available_slots(), 2);
        cwnd.on_send();
        cwnd.on_send();
        assert!(!cwnd.can_send());
        assert_eq!(cwnd.available_slots(), 0);
    }

    #[test]
    fn slow_start_grows_exponentially() {
        let mut cwnd = CongestionWindow::new(1.0, 64.0, 300.0);
        // In slow start, each ACK adds 1 to cwnd
        cwnd.on_send();
        cwnd.on_ack();
        assert_eq!(cwnd.window_size(), 2);

        cwnd.on_send();
        cwnd.on_send();
        cwnd.on_ack();
        cwnd.on_ack();
        assert_eq!(cwnd.window_size(), 4);
    }

    #[test]
    fn congestion_avoidance_grows_linearly() {
        let mut cwnd = CongestionWindow::new(10.0, 8.0, 300.0);
        // cwnd > ssthresh, so we're in congestion avoidance
        let initial = cwnd.window_size();
        // Need ~10 ACKs to grow by 1 (1/cwnd per ACK)
        for _ in 0..10 {
            cwnd.on_send();
            cwnd.on_ack();
        }
        // Should have grown by ~1
        assert!(cwnd.window_size() >= initial);
        assert!(cwnd.window_size() <= initial + 2);
    }

    #[test]
    fn timeout_reduces_window() {
        let mut cwnd = CongestionWindow::new(16.0, 64.0, 300.0);
        cwnd.on_send();
        cwnd.on_timeout();
        // ssthresh = 16/2 = 8, cwnd = 1 (min)
        assert_eq!(cwnd.window_size(), 1);
        assert_eq!(cwnd.ssthresh(), 8.0);
    }

    #[test]
    fn respects_max_cwnd() {
        let mut cwnd = CongestionWindow::new(299.0, 10.0, 300.0);
        cwnd.on_send();
        cwnd.on_ack();
        cwnd.on_send();
        cwnd.on_ack();
        assert!(cwnd.window_size() <= 300);
    }

    #[test]
    fn drop_only_decrements_outstanding() {
        let mut cwnd = CongestionWindow::new(4.0, 64.0, 300.0);
        cwnd.on_send();
        cwnd.on_send();
        assert_eq!(cwnd.outstanding(), 2);
        cwnd.on_drop();
        assert_eq!(cwnd.outstanding(), 1);
        // Window size unchanged
        assert_eq!(cwnd.window_size(), 4);
    }

    #[test]
    fn nan_inputs_sanitized() {
        let cwnd = CongestionWindow::new(f64::NAN, f64::NAN, f64::NAN);
        // Should fallback to safe defaults
        assert_eq!(cwnd.window_size(), 1); // initial_cwnd clamped to 1.0
        assert!(cwnd.can_send());
    }

    #[test]
    fn infinity_inputs_sanitized() {
        let cwnd = CongestionWindow::new(f64::INFINITY, f64::INFINITY, f64::INFINITY);
        // max_cwnd not finite → 300.0 default, initial clamped to min(1.0, 300.0)=1.0
        assert_eq!(cwnd.window_size(), 1);
    }

    #[test]
    fn zero_inputs_sanitized() {
        let cwnd = CongestionWindow::new(0.0, 0.0, 0.0);
        assert_eq!(cwnd.window_size(), 1);
        assert!(cwnd.can_send());
    }
}
