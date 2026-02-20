use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rustmap_types::HostStatus;

/// Tracks discovery state for each target host.
///
/// Simpler than `ProbeTracker` — we only need per-host tracking (not per-port).
/// ANY response from a target IP marks it as "up".
pub struct DiscoveryTracker {
    hosts: DashMap<IpAddr, HostDiscoveryState>,
    total_hosts: usize,
}

struct HostDiscoveryState {
    status: HostStatus,
    /// Timestamp of the most recent probe sent for this host.
    /// Updated on each probe send so that latency reflects the actual
    /// probe-to-response time rather than tracker creation time.
    last_probe_sent: Instant,
    latency: Option<Duration>,
    probes_sent: u32,
}

/// Result of discovery for a single host.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub ip: IpAddr,
    pub status: HostStatus,
    pub latency: Option<Duration>,
}

impl DiscoveryTracker {
    /// Create a new tracker and register all target hosts.
    pub fn new(targets: &[IpAddr]) -> Self {
        let hosts = DashMap::new();
        let now = Instant::now();
        for &ip in targets {
            hosts.insert(
                ip,
                HostDiscoveryState {
                    status: HostStatus::Down,
                    last_probe_sent: now,
                    latency: None,
                    probes_sent: 0,
                },
            );
        }
        Self {
            total_hosts: targets.len(),
            hosts,
        }
    }

    /// Record that a probe was sent for a host.
    /// Updates the last probe send time so that latency reflects the
    /// most recent probe-to-response time.
    pub fn on_probe_sent(&self, ip: IpAddr) {
        if let Some(mut entry) = self.hosts.get_mut(&ip) {
            entry.last_probe_sent = Instant::now();
            entry.probes_sent += 1;
        }
    }

    /// Record a response from a host.
    /// Returns `true` if this is the first response (newly marked Up).
    pub fn on_response(&self, ip: IpAddr) -> bool {
        if let Some(mut entry) = self.hosts.get_mut(&ip) {
            if entry.status == HostStatus::Up {
                return false; // Already marked up
            }
            let latency = entry.last_probe_sent.elapsed();
            entry.status = HostStatus::Up;
            entry.latency = Some(latency);
            true
        } else {
            false // Not one of our targets
        }
    }

    /// Check if a given IP is one of our targets.
    pub fn is_target(&self, ip: &IpAddr) -> bool {
        self.hosts.contains_key(ip)
    }

    /// Check if a host has already been resolved as Up.
    pub fn is_host_up(&self, ip: &IpAddr) -> bool {
        self.hosts
            .get(ip)
            .is_some_and(|entry| entry.status == HostStatus::Up)
    }

    /// Check if all hosts have been resolved (either Up, or probes sent with
    /// no response pending). Returns true when no hosts remain that could
    /// still transition from Down to Up — i.e., all hosts are either Up or
    /// have had probes sent and sufficient time has passed.
    pub fn all_resolved(&self) -> bool {
        // Consider resolved when every host is either Up or has had at
        // least one probe sent (meaning it is legitimately Down if no
        // response arrives during the grace period).
        self.hosts
            .iter()
            .all(|entry| entry.status == HostStatus::Up || entry.probes_sent > 0)
    }

    /// Count how many hosts are Up.
    pub fn up_count(&self) -> usize {
        self.hosts
            .iter()
            .filter(|entry| entry.status == HostStatus::Up)
            .count()
    }

    /// Mark all remaining unresolved hosts as Down.
    pub fn mark_remaining_down(&self) {
        // All hosts that are still Down stay Down (no-op in terms of status,
        // but this signals we've finished checking).
    }

    /// Collect final results.
    pub fn collect_results(&self) -> Vec<DiscoveryResult> {
        self.hosts
            .iter()
            .map(|entry| DiscoveryResult {
                ip: *entry.key(),
                status: entry.status,
                latency: entry.latency,
            })
            .collect()
    }

    /// Total number of targets being tracked.
    pub fn total_hosts(&self) -> usize {
        self.total_hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn register_and_collect() {
        let targets = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let tracker = DiscoveryTracker::new(&targets);
        assert_eq!(tracker.total_hosts(), 2);
        assert_eq!(tracker.up_count(), 0);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status == HostStatus::Down));
    }

    #[test]
    fn on_response_marks_up() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let tracker = DiscoveryTracker::new(&[ip]);

        assert!(!tracker.is_host_up(&ip));
        let first = tracker.on_response(ip);
        assert!(first);
        assert!(tracker.is_host_up(&ip));

        // Second response should return false
        let second = tracker.on_response(ip);
        assert!(!second);
    }

    #[test]
    fn response_records_latency() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let tracker = DiscoveryTracker::new(&[ip]);

        std::thread::sleep(Duration::from_millis(5));
        tracker.on_response(ip);

        let results = tracker.collect_results();
        let result = results.iter().find(|r| r.ip == ip).unwrap();
        assert!(result.latency.unwrap() >= Duration::from_millis(4));
    }

    #[test]
    fn unknown_ip_ignored() {
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let unknown = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let tracker = DiscoveryTracker::new(&[target]);

        assert!(!tracker.is_target(&unknown));
        assert!(!tracker.on_response(unknown));
    }

    #[test]
    fn all_resolved_when_all_up() {
        let targets = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let tracker = DiscoveryTracker::new(&targets);

        assert!(!tracker.all_resolved());

        tracker.on_response(targets[0]);
        assert!(!tracker.all_resolved());

        tracker.on_response(targets[1]);
        assert!(tracker.all_resolved());
    }

    #[test]
    fn probe_sent_count() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let tracker = DiscoveryTracker::new(&[ip]);

        tracker.on_probe_sent(ip);
        tracker.on_probe_sent(ip);
        tracker.on_probe_sent(ip);

        let entry = tracker.hosts.get(&ip).unwrap();
        assert_eq!(entry.probes_sent, 3);
    }
}
