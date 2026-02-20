<script lang="ts">
  import type { OsFingerprint } from "../../types";

  interface Props {
    fingerprint: OsFingerprint;
  }

  let { fingerprint }: Props = $props();

  const osLabel = $derived(
    [fingerprint.os_family, fingerprint.os_generation]
      .filter(Boolean)
      .join(" ") || null,
  );
</script>

{#if osLabel}
  <div class="os-info">
    <h4 class="section-title">OS Detection</h4>
    <div class="os-match">
      <span class="os-name">{osLabel}</span>
      {#if fingerprint.accuracy != null}
        <span class="os-accuracy mono text-muted">{fingerprint.accuracy}%</span>
      {/if}
    </div>
  </div>
{/if}

<style>
  .os-info {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .section-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .os-match {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    font-size: 13px;
  }

  .os-name {
    font-weight: 500;
  }

  .os-accuracy {
    font-size: 12px;
  }
</style>
