<script lang="ts">
  import { save } from "@tauri-apps/plugin-dialog";
  import { scanState } from "../../stores/scanState.svelte";
  import { exportToFile } from "../../tauri/commands";

  let format = $state("json");
  let exporting = $state(false);
  let statusMsg = $state("");
  let statusType = $state<"success" | "error" | "">("");

  const extensions: Record<string, string> = {
    json: "json",
    xml: "xml",
    normal: "txt",
    grepable: "gnmap",
  };

  const filterNames: Record<string, string> = {
    json: "JSON",
    xml: "XML",
    normal: "Text",
    grepable: "Grepable",
  };

  function showStatus(msg: string, type: "success" | "error") {
    statusMsg = msg;
    statusType = type;
    setTimeout(() => {
      statusMsg = "";
      statusType = "";
    }, 3000);
  }

  async function handleExport() {
    if (!scanState.scanId || exporting) return;

    const ext = extensions[format] ?? "txt";
    const path = await save({
      defaultPath: `rustmap-scan.${ext}`,
      filters: [
        { name: filterNames[format] ?? format, extensions: [ext] },
        { name: "All Files", extensions: ["*"] },
      ],
    });

    if (!path) return; // User cancelled

    exporting = true;
    try {
      await exportToFile(scanState.scanId, format, path);
      showStatus("Saved", "success");
    } catch (e) {
      console.error("Export failed:", e);
      showStatus("Export failed", "error");
    } finally {
      exporting = false;
    }
  }
</script>

<div class="export">
  <select class="select" bind:value={format}>
    <option value="json">JSON</option>
    <option value="xml">XML</option>
    <option value="normal">Normal</option>
    <option value="grepable">Grepable</option>
  </select>
  <button class="btn" onclick={handleExport} disabled={exporting}>
    {exporting ? "Saving..." : "Export"}
  </button>
  {#if statusMsg}
    <span class="status {statusType}">{statusMsg}</span>
  {/if}
</div>

<style>
  .export {
    display: flex;
    gap: var(--space-xs);
    align-items: center;
  }

  .select {
    background: var(--bg-base);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    padding: var(--space-xs) var(--space-sm);
    font-size: 12px;
  }

  .btn {
    padding: var(--space-xs) var(--space-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 12px;
    cursor: pointer;
  }

  .btn:hover:not(:disabled) {
    background: var(--border-default);
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .status {
    font-size: 11px;
    font-weight: 500;
  }

  .status.success {
    color: var(--accent-green, #4ade80);
  }

  .status.error {
    color: var(--accent-red, #f87171);
  }
</style>
