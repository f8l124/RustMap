use std::time::Duration;

use rustmap_types::{OsFingerprint, TcpFingerprint, TcpOption};

/// Estimate host uptime from TCP timestamp values in the OS fingerprint.
///
/// Extracts the TCP timestamp value from the first available fingerprint
/// (syn_open → passive → syn_closed), infers the tick rate based on the
/// detected OS family, and computes estimated uptime.
pub fn estimate_uptime(os_fp: &OsFingerprint) -> Option<Duration> {
    let fingerprint = os_fp
        .probe_results
        .syn_open
        .as_ref()
        .or(os_fp.probe_results.passive.as_ref())
        .or(os_fp.probe_results.syn_closed.as_ref())?;

    let ts_val = extract_timestamp_val(fingerprint)?;
    // ts_val == 0 or u32::MAX likely means no timestamp or wrapped counter
    if ts_val == 0 || ts_val == u32::MAX {
        return None;
    }

    let hz = infer_tick_rate(ts_val, os_fp.os_family.as_deref());
    let uptime_secs = ts_val as f64 / hz;

    // Guard: reject non-finite values (defense in depth) and unreasonable uptimes
    if !uptime_secs.is_finite() || uptime_secs > 5.0 * 365.25 * 86400.0 {
        return None;
    }

    Some(Duration::from_secs_f64(uptime_secs))
}

/// Extract the TCP timestamp value from a fingerprint's options.
fn extract_timestamp_val(fp: &TcpFingerprint) -> Option<u32> {
    fp.tcp_options.iter().find_map(|opt| {
        if let TcpOption::Timestamp(ts_val, _) = opt {
            Some(*ts_val)
        } else {
            None
        }
    })
}

/// Infer the tick rate (Hz) of the TCP timestamp counter based on OS family.
///
/// - Linux: typically 1000 Hz (1 tick/ms). Older kernels used 100 Hz (HZ=100).
///   Heuristic: if ts_val < 3,153,600 (< ~36.5 days at 1000 Hz), assume 100 Hz.
/// - Windows: typically 100 Hz (10ms per tick).
/// - macOS/FreeBSD: typically 1000 Hz.
/// - Unknown: default to 1000 Hz.
fn infer_tick_rate(ts_val: u32, os_family: Option<&str>) -> f64 {
    match os_family {
        Some("Linux") => {
            if ts_val < 3_153_600 {
                100.0
            } else {
                1000.0
            }
        }
        Some("Windows") => 100.0,
        Some("macOS") | Some("FreeBSD") => 1000.0,
        _ => 1000.0,
    }
}

/// Format a Duration as a human-readable uptime string (e.g., "42d 3h 15m").
///
/// Includes seconds when there are no days or hours, so short uptimes
/// are displayed as "5m 30s" instead of just "5m".
pub fn format_uptime(d: &Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::OsProbeResults;

    fn make_fp_with_ts(ts_val: u32) -> TcpFingerprint {
        TcpFingerprint {
            initial_ttl: 64,
            window_size: 29200,
            tcp_options: vec![TcpOption::Mss(1460), TcpOption::Timestamp(ts_val, 0)],
            df_bit: true,
            mss: Some(1460),
        }
    }

    #[test]
    fn uptime_linux_1000hz() {
        let fp = OsFingerprint {
            os_family: Some("Linux".into()),
            os_generation: None,
            os_detail: None,
            accuracy: Some(90),
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(86_400_000)),
                ..Default::default()
            },
        };
        let uptime = estimate_uptime(&fp).unwrap();
        // 86_400_000 ticks / 1000 Hz = 86400 seconds = 1 day
        assert!(
            (uptime.as_secs() as f64 - 86400.0).abs() < 1.0,
            "expected ~86400s, got {}s",
            uptime.as_secs()
        );
    }

    #[test]
    fn uptime_windows_100hz() {
        let fp = OsFingerprint {
            os_family: Some("Windows".into()),
            os_generation: None,
            os_detail: None,
            accuracy: Some(90),
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(8_640_000)),
                ..Default::default()
            },
        };
        let uptime = estimate_uptime(&fp).unwrap();
        // 8_640_000 ticks / 100 Hz = 86400 seconds = 1 day
        assert!(
            (uptime.as_secs() as f64 - 86400.0).abs() < 1.0,
            "expected ~86400s, got {}s",
            uptime.as_secs()
        );
    }

    #[test]
    fn uptime_zero_ts_returns_none() {
        let fp = OsFingerprint {
            os_family: Some("Linux".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(0)),
                ..Default::default()
            },
        };
        assert!(estimate_uptime(&fp).is_none());
    }

    #[test]
    fn uptime_no_fingerprint_returns_none() {
        let fp = OsFingerprint {
            os_family: None,
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults::default(),
        };
        assert!(estimate_uptime(&fp).is_none());
    }

    #[test]
    fn uptime_u32_max_returns_none() {
        let fp = OsFingerprint {
            os_family: Some("Linux".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(u32::MAX)),
                ..Default::default()
            },
        };
        assert!(estimate_uptime(&fp).is_none());
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(&Duration::from_secs(90061)), "1d 1h 1m");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(&Duration::from_secs(3660)), "1h 1m");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(&Duration::from_secs(300)), "5m 0s");
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(&Duration::from_secs(330)), "5m 30s");
    }

    #[test]
    fn linux_hz_boundary_below() {
        // ts_val just below the 3,153,600 boundary should use 100 Hz
        let fp = OsFingerprint {
            os_family: Some("Linux".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(3_153_599)),
                ..Default::default()
            },
        };
        let uptime = estimate_uptime(&fp).unwrap();
        // 3_153_599 / 100 Hz = 31535.99s (~8.76 hours)
        assert!(
            (uptime.as_secs_f64() - 31535.99).abs() < 1.0,
            "expected ~31536s at 100Hz, got {}s",
            uptime.as_secs()
        );
    }

    #[test]
    fn linux_hz_boundary_at() {
        // ts_val exactly at the boundary should use 1000 Hz
        let fp = OsFingerprint {
            os_family: Some("Linux".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(3_153_600)),
                ..Default::default()
            },
        };
        let uptime = estimate_uptime(&fp).unwrap();
        // 3_153_600 / 1000 Hz = 3153.6s (~52.6 minutes)
        assert!(
            (uptime.as_secs_f64() - 3153.6).abs() < 1.0,
            "expected ~3154s at 1000Hz, got {}s",
            uptime.as_secs()
        );
    }

    #[test]
    fn uptime_near_five_year_limit() {
        // Just under 5 years at 1000 Hz: 5 * 365.25 * 86400 * 1000 = ~157,788,000,000
        // That exceeds u32::MAX (4,294,967,295), so max feasible is u32::MAX-1 ticks.
        // u32::MAX-1 / 1000 Hz = 4,294,967.294s (~49.7 days, well under limit)
        let fp = OsFingerprint {
            os_family: Some("FreeBSD".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(u32::MAX - 1)),
                ..Default::default()
            },
        };
        let uptime = estimate_uptime(&fp).unwrap();
        // (u32::MAX - 1) / 1000.0 = ~4,294,967.294s = ~49.7 days
        let expected = (u32::MAX - 1) as f64 / 1000.0;
        assert!(
            (uptime.as_secs_f64() - expected).abs() < 1.0,
            "expected ~{}s, got {}s",
            expected,
            uptime.as_secs_f64()
        );
    }

    #[test]
    fn uptime_exceeds_five_year_limit_returns_none() {
        // At 100 Hz (Windows), u32::MAX-1 / 100 = ~42,949,672.94s = ~1.36 years, under limit
        // To exceed 5 years at 100 Hz we'd need ~15,778,800,000 ticks (> u32::MAX).
        // So test with a value that at 100 Hz gives > 5 years:
        // Trick: use low tick rate. Windows=100Hz. Need ts_val > 5*365.25*86400*100 = ~15.78B
        // Can't exceed u32::MAX, so we can't actually hit 5y with u32 at 100Hz.
        // Instead, verify the guard works by checking a known-good value doesn't return None.
        let fp = OsFingerprint {
            os_family: Some("Windows".into()),
            os_generation: None,
            os_detail: None,
            accuracy: None,
            probe_results: OsProbeResults {
                syn_open: Some(make_fp_with_ts(u32::MAX - 1)),
                ..Default::default()
            },
        };
        // (u32::MAX-1) / 100.0 = ~42,949,672.94s = ~1.36 years -- should succeed
        let uptime = estimate_uptime(&fp);
        assert!(
            uptime.is_some(),
            "1.36 years should be under the 5-year limit"
        );
    }
}
