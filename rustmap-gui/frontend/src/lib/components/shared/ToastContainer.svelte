<script lang="ts">
  import { toasts } from "../../stores/toast.svelte";
</script>

{#if toasts.toasts.length > 0}
  <div class="toast-container" aria-live="polite" aria-atomic="false">
    {#each toasts.toasts as toast (toast.id)}
      <div class="toast toast-{toast.type}">
        <span class="toast-message">{toast.message}</span>
        <button class="toast-close" onclick={() => toasts.dismiss(toast.id)} aria-label="Dismiss">{"\u2715"}</button>
      </div>
    {/each}
  </div>
{/if}

<style>
  .toast-container {
    position: fixed;
    bottom: 36px;
    right: 16px;
    z-index: 1000;
    display: flex;
    flex-direction: column-reverse;
    gap: var(--space-sm);
    max-width: 360px;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--radius-md);
    font-size: 13px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    animation: toast-in 0.2s ease-out;
  }

  @keyframes toast-in {
    from {
      opacity: 0;
      transform: translateY(8px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .toast-success {
    background: var(--bg-elevated);
    border: 1px solid var(--status-success);
    color: var(--status-success);
  }

  .toast-error {
    background: var(--bg-elevated);
    border: 1px solid var(--status-error);
    color: var(--status-error);
  }

  .toast-warning {
    background: var(--bg-elevated);
    border: 1px solid var(--status-warning);
    color: var(--status-warning);
  }

  .toast-info {
    background: var(--bg-elevated);
    border: 1px solid var(--status-info);
    color: var(--status-info);
  }

  .toast-message {
    flex: 1;
    color: var(--text-primary);
  }

  .toast-close {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 12px;
    padding: 0 2px;
    opacity: 0.7;
    flex-shrink: 0;
  }

  .toast-close:hover {
    opacity: 1;
  }
</style>
