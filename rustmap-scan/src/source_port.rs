use std::sync::atomic::{AtomicU16, Ordering};

/// Ephemeral source port range for SYN scan probe correlation.
const PORT_MIN: u16 = 40000;
const PORT_MAX: u16 = 59999;
const PORT_RANGE: u16 = PORT_MAX - PORT_MIN + 1;

/// Thread-safe atomic source port allocator.
///
/// Allocates unique source ports in the range 40000-59999 for SYN probes.
/// Each probe uses a different source port so we can correlate responses
/// back to the correct probe via `(dest_ip, dest_port, source_port)`.
pub struct SourcePortAllocator {
    counter: AtomicU16,
    /// If set, always return this fixed port instead of cycling.
    fixed_port: Option<u16>,
}

impl SourcePortAllocator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU16::new(0),
            fixed_port: None,
        }
    }

    /// Create an allocator that always returns the same port.
    /// Used for source port spoofing (`-g` / `--source-port`).
    pub fn new_fixed(port: u16) -> Self {
        Self {
            counter: AtomicU16::new(0),
            fixed_port: Some(port),
        }
    }

    /// Allocate the next source port. Wraps around within the range,
    /// or returns the fixed port if configured.
    pub fn next_port(&self) -> u16 {
        if let Some(port) = self.fixed_port {
            return port;
        }
        loop {
            let current = self.counter.load(Ordering::Relaxed);
            let next = if current + 1 >= PORT_RANGE {
                0
            } else {
                current + 1
            };
            if self
                .counter
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return PORT_MIN + current;
            }
        }
    }
}

impl Default for SourcePortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_in_range() {
        let alloc = SourcePortAllocator::new();
        for _ in 0..100 {
            let port = alloc.next_port();
            assert!(
                (PORT_MIN..=PORT_MAX).contains(&port),
                "port {port} out of range"
            );
        }
    }

    #[test]
    fn allocates_sequentially() {
        let alloc = SourcePortAllocator::new();
        let p1 = alloc.next_port();
        let p2 = alloc.next_port();
        assert_eq!(p2, p1 + 1);
    }

    #[test]
    fn wraps_around() {
        let alloc = SourcePortAllocator::new();
        // Exhaust the range
        for _ in 0..PORT_RANGE {
            alloc.next_port();
        }
        // Next should wrap back to PORT_MIN
        let wrapped = alloc.next_port();
        assert_eq!(wrapped, PORT_MIN);
    }

    #[test]
    fn fixed_port_always_returns_same() {
        let alloc = SourcePortAllocator::new_fixed(53);
        for _ in 0..100 {
            assert_eq!(alloc.next_port(), 53);
        }
    }

    #[test]
    fn thread_safe() {
        use std::sync::Arc;
        let alloc = Arc::new(SourcePortAllocator::new());
        let mut handles = vec![];
        for _ in 0..4 {
            let a = alloc.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let p = a.next_port();
                    assert!((PORT_MIN..=PORT_MAX).contains(&p));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
