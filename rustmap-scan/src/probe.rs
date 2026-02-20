use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rustmap_types::PortState;

/// Unique key for correlating a probe with its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub src_port: u16,
}

/// State of a probe in-flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    Sent,
    Responded(PortState),
    TimedOut,
}

/// Record for a single outstanding probe.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    pub key: ProbeKey,
    pub state: ProbeState,
    pub sent_at: Instant,
    pub rto: Duration,
    pub retries_remaining: u8,
}

/// State priority for upgrading port results: Open > Closed > Filtered > OpenFiltered.
/// Higher value = higher priority (preferred result).
fn state_priority(state: PortState) -> u8 {
    match state {
        PortState::Open => 4,
        PortState::Closed => 3,
        PortState::Filtered => 2,
        PortState::OpenFiltered => 1,
        PortState::Unfiltered => 3,
        PortState::ClosedFiltered => 1,
    }
}

/// Thread-safe probe tracker using DashMap.
///
/// Tracks all in-flight probes and their states. Used by the SYN scanner's
/// three concurrent tasks (send loop, response processor, timeout checker).
pub struct ProbeTracker {
    probes: DashMap<ProbeKey, ProbeRecord>,
    /// Port results indexed by destination port.
    results: DashMap<u16, PortState>,
}

impl ProbeTracker {
    pub fn new() -> Self {
        Self {
            probes: DashMap::new(),
            results: DashMap::new(),
        }
    }

    /// Register a new probe as sent.
    pub fn register_probe(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_port: u16,
        rto: Duration,
        max_retries: u8,
    ) -> ProbeKey {
        let key = ProbeKey {
            dst_ip,
            dst_port,
            src_port,
        };
        let record = ProbeRecord {
            key,
            state: ProbeState::Sent,
            sent_at: Instant::now(),
            rto,
            retries_remaining: max_retries,
        };
        self.probes.insert(key, record);
        key
    }

    /// Called when a response is received. Returns the RTT if the probe was found.
    /// Updates probe state and records the port result.
    pub fn on_response(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        src_port: u16,
        port_state: PortState,
    ) -> Option<Duration> {
        let key = ProbeKey {
            dst_ip,
            dst_port,
            src_port,
        };
        let mut entry = self.probes.get_mut(&key)?;

        if entry.state != ProbeState::Sent {
            return None; // Already handled
        }

        let rtt = entry.sent_at.elapsed();
        entry.state = ProbeState::Responded(port_state);

        // Record the result, upgrading state if the new result has higher priority.
        // Priority: Open > Closed > Filtered > OpenFiltered
        self.results
            .entry(dst_port)
            .and_modify(|existing| {
                if state_priority(port_state) > state_priority(*existing) {
                    *existing = port_state;
                }
            })
            .or_insert(port_state);

        Some(rtt)
    }

    /// Collect probes that have exceeded their RTO.
    /// Returns keys of timed-out probes that still have retries remaining.
    ///
    /// Uses a two-pass approach: first collects keys with an immutable iterator
    /// to avoid holding mutable DashMap locks across the entire scan, then
    /// mutates only the expired entries in a second pass.
    pub fn collect_timed_out(&self) -> (Vec<ProbeKey>, Vec<ProbeKey>) {
        let now = Instant::now();
        let mut retryable = Vec::new();
        let mut expired_keys = Vec::new();

        // Pass 1: read-only scan to identify timed-out probes.
        for entry in self.probes.iter() {
            if entry.state != ProbeState::Sent {
                continue;
            }
            if now.duration_since(entry.sent_at) < entry.rto {
                continue;
            }

            if entry.retries_remaining > 0 {
                retryable.push(entry.key);
            } else {
                expired_keys.push(entry.key);
            }
        }

        // Pass 2: mutate only the expired entries (no retries left).
        for key in &expired_keys {
            if let Some(mut entry) = self.probes.get_mut(key) {
                entry.state = ProbeState::TimedOut;
            }
        }

        (retryable, expired_keys)
    }

    /// Mark a probe for retry: decrement retries and mark timed out.
    /// Returns `(dst_port, remaining_retries)` so it can be re-sent.
    pub fn prepare_retry(&self, key: &ProbeKey) -> Option<(u16, u8)> {
        let mut entry = self.probes.get_mut(key)?;
        if entry.retries_remaining > 0 {
            entry.retries_remaining -= 1;
            let remaining = entry.retries_remaining;
            entry.state = ProbeState::TimedOut;
            Some((key.dst_port, remaining))
        } else {
            None
        }
    }

    /// Remove a probe entry (after retry or expiry).
    pub fn remove(&self, key: &ProbeKey) {
        self.probes.remove(key);
    }

    /// Mark a probe as having no response, with the given port state.
    ///
    /// For SYN/ACK/Window scans, `state` is typically `PortState::Filtered`.
    /// For FIN/NULL/Xmas/Maimon scans, `state` is typically `PortState::OpenFiltered`.
    pub fn mark_no_response(&self, key: &ProbeKey, state: PortState) {
        if let Some(mut entry) = self.probes.get_mut(key) {
            entry.state = ProbeState::TimedOut;
        }
        // Only set the state if no other result exists for this port
        self.results.entry(key.dst_port).or_insert(state);
    }

    /// Check if all probes for this host have completed (responded or timed out).
    pub fn is_complete(&self) -> bool {
        self.probes.iter().all(|e| e.state != ProbeState::Sent)
    }

    /// Number of probes still in-flight (state == Sent).
    pub fn outstanding_count(&self) -> usize {
        self.probes
            .iter()
            .filter(|e| e.state == ProbeState::Sent)
            .count()
    }

    /// Collect final results for all ports.
    pub fn collect_results(&self) -> Vec<(u16, PortState)> {
        self.results
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect()
    }
}

impl Default for ProbeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn register_and_respond() {
        let tracker = ProbeTracker::new();
        tracker.register_probe(test_ip(), 80, 40001, Duration::from_secs(1), 3);

        assert_eq!(tracker.outstanding_count(), 1);
        assert!(!tracker.is_complete());

        let rtt = tracker.on_response(test_ip(), 80, 40001, PortState::Open);
        assert!(rtt.is_some());
        assert_eq!(tracker.outstanding_count(), 0);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (80, PortState::Open));
    }

    #[test]
    fn duplicate_response_ignored() {
        let tracker = ProbeTracker::new();
        tracker.register_probe(test_ip(), 443, 40002, Duration::from_secs(1), 3);

        let rtt1 = tracker.on_response(test_ip(), 443, 40002, PortState::Open);
        let rtt2 = tracker.on_response(test_ip(), 443, 40002, PortState::Open);
        assert!(rtt1.is_some());
        assert!(rtt2.is_none()); // Second response ignored
    }

    #[test]
    fn unknown_response_ignored() {
        let tracker = ProbeTracker::new();
        let rtt = tracker.on_response(test_ip(), 22, 40099, PortState::Open);
        assert!(rtt.is_none());
    }

    #[test]
    fn timeout_with_retries() {
        let tracker = ProbeTracker::new();
        tracker.register_probe(
            test_ip(),
            80,
            40001,
            Duration::from_millis(1), // Very short RTO for test
            2,
        );

        // Wait for it to expire
        std::thread::sleep(Duration::from_millis(5));

        let (retryable, expired) = tracker.collect_timed_out();
        assert_eq!(retryable.len(), 1);
        assert_eq!(expired.len(), 0);

        // Prepare retry — returns (port, remaining_retries)
        let result = tracker.prepare_retry(&retryable[0]);
        assert_eq!(result, Some((80, 1)));
    }

    #[test]
    fn timeout_no_retries_marks_expired() {
        let tracker = ProbeTracker::new();
        tracker.register_probe(
            test_ip(),
            80,
            40001,
            Duration::from_millis(1),
            0, // No retries
        );

        std::thread::sleep(Duration::from_millis(5));

        let (retryable, expired) = tracker.collect_timed_out();
        assert_eq!(retryable.len(), 0);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn mark_no_response_filtered() {
        let tracker = ProbeTracker::new();
        let key = tracker.register_probe(test_ip(), 80, 40001, Duration::from_secs(1), 0);
        tracker.mark_no_response(&key, PortState::Filtered);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, PortState::Filtered);
    }

    #[test]
    fn mark_no_response_open_filtered() {
        let tracker = ProbeTracker::new();
        let key = tracker.register_probe(test_ip(), 80, 40001, Duration::from_secs(1), 0);
        tracker.mark_no_response(&key, PortState::OpenFiltered);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, PortState::OpenFiltered);
    }

    #[test]
    fn multiple_ports() {
        let tracker = ProbeTracker::new();
        tracker.register_probe(test_ip(), 80, 40001, Duration::from_secs(1), 0);
        tracker.register_probe(test_ip(), 443, 40002, Duration::from_secs(1), 0);
        tracker.register_probe(test_ip(), 22, 40003, Duration::from_secs(1), 0);

        assert_eq!(tracker.outstanding_count(), 3);

        tracker.on_response(test_ip(), 80, 40001, PortState::Open);
        tracker.on_response(test_ip(), 443, 40002, PortState::Closed);

        assert_eq!(tracker.outstanding_count(), 1);
        assert!(!tracker.is_complete());

        let results = tracker.collect_results();
        assert_eq!(results.len(), 2);
    }
}
