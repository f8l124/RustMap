<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    variant?: "success" | "error" | "warning" | "info" | "muted";
    children: Snippet;
  }

  let { variant = "muted", children }: Props = $props();
</script>

<span class="badge badge-{variant}">
  {@render children()}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 1px 8px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 600;
    font-family: var(--font-mono);
  }

  .badge-success {
    background: rgba(45, 212, 168, 0.15);
    color: var(--port-open);
  }

  .badge-error {
    background: rgba(255, 92, 92, 0.15);
    color: var(--port-closed);
  }

  .badge-warning {
    background: rgba(255, 201, 77, 0.15);
    color: var(--port-filtered);
  }

  .badge-info {
    background: rgba(79, 140, 255, 0.15);
    color: var(--accent);
  }

  .badge-muted {
    background: rgba(108, 108, 128, 0.15);
    color: var(--text-muted);
  }
</style>
