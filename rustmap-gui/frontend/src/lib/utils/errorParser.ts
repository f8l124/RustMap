import type { ErrorKind } from "../stores/scanState.svelte";

export function parseError(e: unknown): { message: string; kind: ErrorKind } {
  if (typeof e === "string") {
    const lower = e.toLowerCase();
    if (lower.includes("privilege") || lower.includes("permission") || lower.includes("access denied") || lower.includes("administrator")) {
      return { message: e, kind: "privilege" };
    }
    if (lower.includes("invalid") || lower.includes("target") || lower.includes("port")) {
      return { message: e, kind: "config" };
    }
    return { message: e, kind: "scan" };
  }
  if (e && typeof e === "object") {
    const obj = e as Record<string, unknown>;
    const msg = typeof obj.message === "string" ? obj.message : JSON.stringify(e);
    return parseError(msg);
  }
  return { message: String(e), kind: "backend" };
}
