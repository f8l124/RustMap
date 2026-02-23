<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    title: string;
    open?: boolean;
    children: Snippet;
  }

  let { title, open = $bindable(false), children }: Props = $props();
</script>

<div class="collapsible">
  <button class="header" aria-expanded={open} onclick={() => (open = !open)}>
    <span class="arrow" class:open>{open ? "\u25BC" : "\u25B6"}</span>
    <span class="title">{title}</span>
  </button>
  {#if open}
    <div class="content">
      {@render children()}
    </div>
  {/if}
</div>

<style>
  .collapsible {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .header {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    width: 100%;
    padding: var(--space-sm) var(--space-md);
    background: none;
    border: none;
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    cursor: pointer;
  }

  .header:hover {
    color: var(--text-primary);
  }

  .arrow {
    font-size: 10px;
    transition: transform 0.15s;
  }

  .content {
    padding: var(--space-sm) var(--space-md) var(--space-md);
  }
</style>
