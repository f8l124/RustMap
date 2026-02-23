<script lang="ts">
  import { onMount } from "svelte";
  import Layout from "./lib/components/layout/Layout.svelte";
  import ShortcutsHelp from "./lib/components/shared/ShortcutsHelp.svelte";
  import { setupEventListeners } from "./lib/tauri/events";
  import { checkPrivileges, exportResults, startScan, stopScan } from "./lib/tauri/commands";
  import { privileges } from "./lib/stores/privileges.svelte";
  import { scanState } from "./lib/stores/scanState.svelte";
  import { scanConfig } from "./lib/stores/scanConfig.svelte";
  import { handleGlobalKeydown, registerShortcut } from "./lib/utils/shortcuts";
  import { parseError } from "./lib/utils/errorParser";
  import ToastContainer from "./lib/components/shared/ToastContainer.svelte";
  import { toasts } from "./lib/stores/toast.svelte";
  import { updater } from "./lib/stores/updater.svelte";

  let showShortcuts = $state(false);

  onMount(() => {
    const cleanup = setupEventListeners();
    checkPrivileges().then((info) => {
      privileges.set(info);
    });
    // Check for updates after a brief delay to avoid blocking startup
    setTimeout(() => updater.checkForUpdates(), 3000);

    const unregister = [
      registerShortcut({
        key: "Enter",
        ctrl: true,
        label: "Enter",
        description: "Start scan",
        action: async () => {
          if (!scanConfig.configValid || scanState.isScanning) return;
          scanState.onStarting();
          try {
            await startScan(scanConfig.config);
          } catch (e) {
            const { message, kind } = parseError(e);
            scanState.onScanError(message, kind);
          }
        },
      }),
      registerShortcut({
        key: "Escape",
        label: "Esc",
        description: "Stop scan",
        action: async () => {
          if (showShortcuts) {
            showShortcuts = false;
            return;
          }
          if (scanState.scanId && scanState.isScanning) {
            try {
              await stopScan(scanState.scanId);
            } catch (e) {
              console.error("Failed to stop scan:", e);
            }
          }
        },
      }),
      registerShortcut({
        key: "e",
        ctrl: true,
        label: "E",
        description: "Export results (JSON to clipboard)",
        action: async () => {
          if (!scanState.scanId || scanState.phase !== "complete") return;
          try {
            const output = await exportResults(scanState.scanId, "json");
            await navigator.clipboard.writeText(output);
            toasts.success("Results copied to clipboard");
          } catch (e) {
            toasts.error("Export failed: " + String(e));
          }
        },
      }),
      registerShortcut({
        key: "l",
        ctrl: true,
        label: "L",
        description: "Clear results",
        action: () => {
          if (!scanState.isScanning) {
            scanState.reset();
          }
        },
      }),
      registerShortcut({
        key: "f",
        ctrl: true,
        label: "F",
        description: "Focus filter bar",
        action: () => {
          const el = document.getElementById("filter-search");
          if (el) el.focus();
        },
      }),
      registerShortcut({
        key: "?",
        label: "?",
        description: "Show keyboard shortcuts",
        action: () => {
          showShortcuts = !showShortcuts;
        },
      }),
      registerShortcut({
        key: "F1",
        label: "F1",
        description: "Show keyboard shortcuts",
        action: () => {
          showShortcuts = !showShortcuts;
        },
      }),
    ];

    return () => {
      cleanup();
      for (const unreg of unregister) unreg();
    };
  });
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<Layout />
<ShortcutsHelp visible={showShortcuts} onclose={() => (showShortcuts = false)} />
<ToastContainer />
