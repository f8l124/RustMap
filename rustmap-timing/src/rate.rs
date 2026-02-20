use std::time::{Duration, Instant};

/// Token-bucket rate limiter for --min-rate / --max-rate.
///
/// Tokens accumulate at `max_rate` per second (up to burst capacity).
/// Each probe consumes one token. If no tokens are available, the caller
/// must wait until enough time has passed for a token to be generated.
#[derive(Debug)]
pub struct RateLimiter {
    max_rate: f64,
    tokens: f64,
    max_tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create with specified max_rate (packets/sec).
    /// Pass f64::INFINITY for no limit (try_acquire always succeeds).
    /// Zero, negative, and NaN rates are treated as unlimited.
    pub fn new(max_rate: f64) -> Self {
        // Sanitize: zero, negative, and NaN are all treated as unlimited
        let max_rate = if !max_rate.is_finite() || max_rate <= 0.0 {
            f64::INFINITY
        } else {
            max_rate
        };
        let max_tokens = if max_rate.is_infinite() {
            f64::INFINITY
        } else {
            // Allow a burst of up to 1 second worth of tokens
            max_rate.max(1.0)
        };

        Self {
            max_rate,
            tokens: max_tokens, // start with a full bucket
            max_tokens,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns Ok(()) if allowed,
    /// Err(wait_duration) if not.
    pub fn try_acquire(&mut self) -> Result<(), Duration> {
        if self.max_rate.is_infinite() {
            return Ok(());
        }

        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate how long until we have 1 token
            let deficit = 1.0 - self.tokens;
            let wait_secs = deficit / self.max_rate;
            Err(Duration::from_secs_f64(wait_secs))
        }
    }

    /// Block until a token is available.
    pub async fn acquire(&mut self) {
        loop {
            match self.try_acquire() {
                Ok(()) => return,
                Err(wait) => tokio::time::sleep(wait).await,
            }
        }
    }

    /// Check if a token would be available without consuming it.
    /// Returns true if `try_acquire` would succeed.
    pub fn would_allow(&mut self) -> bool {
        if self.max_rate.is_infinite() {
            return true;
        }
        self.refill();
        self.tokens >= 1.0
    }

    /// Update the rate limit dynamically. Resets burst bucket to new capacity.
    /// Zero, negative, and NaN rates are treated as unlimited.
    pub fn set_rate(&mut self, rate: f64) {
        let rate = if !rate.is_finite() || rate <= 0.0 {
            f64::INFINITY
        } else {
            rate
        };
        self.max_rate = rate;
        self.max_tokens = if rate.is_infinite() {
            f64::INFINITY
        } else {
            rate.max(1.0)
        };
        // Reset to full burst capacity at the new rate
        self.tokens = self.max_tokens;
        self.last_refill = Instant::now();
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.max_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infinite_rate_always_allows() {
        let mut limiter = RateLimiter::new(f64::INFINITY);
        for _ in 0..1000 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn starts_with_burst_capacity() {
        let mut limiter = RateLimiter::new(10.0);
        // Should be able to acquire 10 tokens immediately (1 second burst)
        for _ in 0..10 {
            assert!(limiter.try_acquire().is_ok());
        }
        // 11th should fail
        assert!(limiter.try_acquire().is_err());
    }

    #[test]
    fn returns_correct_wait_duration() {
        let mut limiter = RateLimiter::new(10.0);
        // Drain all tokens
        for _ in 0..10 {
            limiter.try_acquire().unwrap();
        }
        // Should need ~100ms for next token at 10/sec
        let wait = limiter.try_acquire().unwrap_err();
        assert!(wait.as_millis() >= 50 && wait.as_millis() <= 150);
    }

    #[test]
    fn set_rate_updates_limit() {
        let mut limiter = RateLimiter::new(10.0);
        limiter.set_rate(1000.0);
        // Should now have much higher burst capacity
        for _ in 0..100 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn zero_rate_treated_as_unlimited() {
        let mut limiter = RateLimiter::new(0.0);
        for _ in 0..1000 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn nan_rate_treated_as_unlimited() {
        let mut limiter = RateLimiter::new(f64::NAN);
        for _ in 0..1000 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn negative_rate_treated_as_unlimited() {
        let mut limiter = RateLimiter::new(-5.0);
        for _ in 0..1000 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn set_rate_zero_becomes_unlimited() {
        let mut limiter = RateLimiter::new(10.0);
        limiter.set_rate(0.0);
        for _ in 0..1000 {
            assert!(limiter.try_acquire().is_ok());
        }
    }

    #[test]
    fn would_allow_does_not_consume() {
        let mut limiter = RateLimiter::new(10.0);
        // Drain to 1 token remaining
        for _ in 0..9 {
            limiter.try_acquire().unwrap();
        }
        // would_allow should return true (1 token left) without consuming
        assert!(limiter.would_allow());
        assert!(limiter.would_allow()); // still true
        // Actually consuming the token
        assert!(limiter.try_acquire().is_ok());
        // Now empty
        assert!(!limiter.would_allow());
    }
}
