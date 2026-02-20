<script lang="ts">
  import { getRegisteredShortcuts, formatShortcutKey } from "../../utils/shortcuts";

  interface Props {
    visible: boolean;
    onclose: () => void;
  }

  let { visible, onclose }: Props = $props();

  const shortcuts = $derived(getRegisteredShortcuts());
</script>

{#if visible}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" onclick={onclose} role="button" tabindex="-1">
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="dialog" onclick={(e) => e.stopPropagation()} role="dialog" aria-label="Keyboard shortcuts" tabindex="-1">
      <div class="dialog-header">
        <h3 class="dialog-title">Keyboard Shortcuts</h3>
        <button class="close-btn" onclick={onclose}>{"\u2715"}</button>
      </div>
      <div class="shortcuts-list">
        {#each shortcuts as shortcut}
          <div class="shortcut-row">
            <kbd class="shortcut-key mono">{formatShortcutKey(shortcut)}</kbd>
            <span class="shortcut-desc">{shortcut.description}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .dialog {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    padding: var(--space-md);
    min-width: 320px;
    max-width: 420px;
  }

  .dialog-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-md);
  }

  .dialog-title {
    font-size: 16px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 16px;
    padding: 2px 6px;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .shortcuts-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .shortcut-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-md);
  }

  .shortcut-key {
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    padding: 2px 8px;
    font-size: 12px;
    color: var(--text-primary);
    white-space: nowrap;
  }

  .shortcut-desc {
    font-size: 13px;
    color: var(--text-secondary);
    text-align: right;
  }
</style>
