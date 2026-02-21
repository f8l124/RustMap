<script lang="ts">
  import { onMount } from "svelte";
  import type { PresetInfo } from "../../types";
  import {
    listPresets,
    savePreset,
    loadPreset,
    deletePreset,
  } from "../../tauri/commands";
  import { scanConfig } from "../../stores/scanConfig.svelte";

  let presets = $state<PresetInfo[]>([]);
  let selectedPreset = $state("");
  let showSaveDialog = $state(false);
  let saveName = $state("");
  let saving = $state(false);
  let statusMsg = $state("");
  let statusType = $state<"success" | "error" | "">("");

  onMount(async () => {
    await refreshPresets();
  });

  async function refreshPresets() {
    try {
      presets = await listPresets();
    } catch (e) {
      console.error("Failed to load presets:", e);
    }
  }

  async function handleLoad() {
    if (!selectedPreset) return;
    try {
      const config = await loadPreset(selectedPreset);
      scanConfig.loadFromConfig(config);
      showStatus("Loaded", "success");
    } catch (e) {
      console.error("Failed to load preset:", e);
      showStatus("Load failed", "error");
    }
  }

  async function handleSave() {
    const name = saveName.trim();
    if (!name || saving) return;
    saving = true;
    try {
      await savePreset(name, scanConfig.config);
      await refreshPresets();
      selectedPreset = name;
      showSaveDialog = false;
      saveName = "";
      showStatus("Saved", "success");
    } catch (e) {
      console.error("Failed to save preset:", e);
      const msg = typeof e === "string" ? e : "Save failed";
      showStatus(msg, "error");
    } finally {
      saving = false;
    }
  }

  async function handleDelete(name: string) {
    try {
      await deletePreset(name);
      if (selectedPreset === name) selectedPreset = "";
      await refreshPresets();
      showStatus("Deleted", "success");
    } catch (e) {
      console.error("Failed to delete preset:", e);
    }
  }

  function showStatus(msg: string, type: "success" | "error") {
    statusMsg = msg;
    statusType = type;
    setTimeout(() => {
      statusMsg = "";
      statusType = "";
    }, 2000);
  }
</script>

<div class="preset-bar">
  <div class="preset-select-group">
    <select class="preset-select" bind:value={selectedPreset} onchange={handleLoad}>
      <option value="">Presets</option>
      {#each presets as preset}
        <option value={preset.name} title="{preset.targets} | {preset.scan_type} | {preset.port_summary}">
          {preset.name}
        </option>
      {/each}
    </select>
    {#if selectedPreset}
      <button
        class="preset-btn icon-btn"
        onclick={() => handleDelete(selectedPreset)}
        title="Delete preset"
      >&times;</button>
    {/if}
  </div>
  <button
    class="preset-btn"
    onclick={() => {
      showSaveDialog = !showSaveDialog;
      if (showSaveDialog) saveName = "";
    }}
  >
    {showSaveDialog ? "Cancel" : "Save Preset"}
  </button>
  {#if statusMsg}
    <span class="preset-status {statusType}">{statusMsg}</span>
  {/if}
</div>
{#if showSaveDialog}
  <div class="save-row">
    <input
      class="save-input"
      type="text"
      placeholder="Preset name..."
      bind:value={saveName}
      onkeydown={(e) => {
        if (e.key === "Enter") handleSave();
        if (e.key === "Escape") showSaveDialog = false;
      }}
    />
    <button
      class="preset-btn confirm-btn"
      onclick={handleSave}
      disabled={saving || !saveName.trim()}
    >
      {saving ? "Saving..." : "Save"}
    </button>
  </div>
{/if}

<style>
  .preset-bar {
    display: flex;
    gap: var(--space-xs);
    align-items: center;
    flex-wrap: wrap;
  }

  .preset-select-group {
    display: flex;
    align-items: center;
    gap: 2px;
  }

  .preset-select {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 12px;
    min-width: 120px;
  }

  .preset-btn {
    padding: var(--space-xs) var(--space-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
  }

  .preset-btn:hover:not(:disabled) {
    color: var(--text-primary);
    background: var(--border-default);
  }

  .preset-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .icon-btn {
    padding: var(--space-xs) 6px;
    font-size: 14px;
    line-height: 1;
  }

  .icon-btn:hover:not(:disabled) {
    color: var(--status-error);
    background: rgba(255, 92, 92, 0.1);
    border-color: var(--status-error);
  }

  .confirm-btn {
    color: var(--accent);
    border-color: var(--accent);
  }

  .confirm-btn:hover:not(:disabled) {
    background: rgba(79, 140, 255, 0.1);
  }

  .preset-status {
    font-size: 11px;
    font-weight: 500;
  }

  .preset-status.success {
    color: var(--accent-green, #4ade80);
  }

  .preset-status.error {
    color: var(--accent-red, #f87171);
  }

  .save-row {
    display: flex;
    gap: var(--space-xs);
    margin-top: var(--space-xs);
  }

  .save-input {
    flex: 1;
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 12px;
  }

  .save-input::placeholder {
    color: var(--text-muted);
  }

  .save-input:focus {
    outline: none;
    border-color: var(--accent);
  }
</style>
