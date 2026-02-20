<script lang="ts">
  interface Props {
    label: string;
    checked: boolean;
  }

  let { label, checked = $bindable() }: Props = $props();
</script>

<label class="toggle">
  <input type="checkbox" class="toggle-input" bind:checked />
  <span class="toggle-track">
    <span class="toggle-thumb"></span>
  </span>
  <span class="toggle-label">{label}</span>
</label>

<style>
  .toggle {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    cursor: pointer;
    user-select: none;
  }

  .toggle-input {
    display: none;
  }

  .toggle-track {
    width: 36px;
    height: 20px;
    background: var(--border-default);
    border-radius: 10px;
    position: relative;
    transition: background 0.2s;
  }

  .toggle-input:checked + .toggle-track {
    background: var(--accent);
  }

  .toggle-thumb {
    width: 16px;
    height: 16px;
    background: #fff;
    border-radius: 50%;
    position: absolute;
    top: 2px;
    left: 2px;
    transition: transform 0.2s;
  }

  .toggle-input:checked + .toggle-track .toggle-thumb {
    transform: translateX(16px);
  }

  .toggle-label {
    font-size: 13px;
    color: var(--text-secondary);
  }
</style>
