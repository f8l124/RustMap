/** Format a {secs, nanos} Duration to human-readable string */
export function formatDuration(d: { secs: number; nanos: number }): string {
  const totalMs = d.secs * 1000 + d.nanos / 1_000_000;
  if (totalMs < 1000) {
    return `${totalMs.toFixed(0)}ms`;
  }
  const totalSecs = totalMs / 1000;
  if (totalSecs < 60) {
    return `${totalSecs.toFixed(2)}s`;
  }
  const mins = Math.floor(totalSecs / 60);
  const secs = totalSecs % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

/** Format a latency duration to ms with 2 decimal places */
export function formatLatency(
  d: { secs: number; nanos: number } | null,
): string {
  if (!d) return "—";
  const ms = d.secs * 1000 + d.nanos / 1_000_000;
  return `${ms.toFixed(2)}ms`;
}

/** Format a Unix timestamp (ms) to local time string */
export function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

/** Format elapsed time from a start timestamp to now */
export function formatElapsed(startMs: number): string {
  const elapsed = Math.floor((Date.now() - startMs) / 1000);
  if (elapsed < 60) return `${elapsed}s`;
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  return `${mins}m ${secs}s`;
}
