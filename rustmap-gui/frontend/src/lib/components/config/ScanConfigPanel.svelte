<script lang="ts">
  import PresetSelector from "./PresetSelector.svelte";
  import TargetInput from "./TargetInput.svelte";
  import PortSelector from "./PortSelector.svelte";
  import ScanTypeSelector from "./ScanTypeSelector.svelte";
  import TimingSelector from "./TimingSelector.svelte";
  import FeatureToggles from "./FeatureToggles.svelte";
  import DiscoveryConfig from "./DiscoveryConfig.svelte";
  import ScriptConfig from "./ScriptConfig.svelte";
  import AdvancedOptions from "./AdvancedOptions.svelte";
  import ScanActions from "./ScanActions.svelte";
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import { privileges } from "../../stores/privileges.svelte";
  import { SCAN_TYPES } from "../../utils/scanTypeInfo";

  const selectedScanType = $derived(
    SCAN_TYPES.find((t) => t.flag === scanConfig.scanType),
  );
  const showPrivilegeWarning = $derived(
    selectedScanType?.requiresPrivilege && !privileges.isPrivileged,
  );
</script>

<section class="config-panel">
  <PresetSelector />
  <div class="config-grid">
    <TargetInput />
    <div class="config-row">
      <PortSelector />
      <ScanTypeSelector />
      <TimingSelector />
    </div>
    <FeatureToggles />
    <DiscoveryConfig />
    <ScriptConfig />
    <AdvancedOptions />
  </div>
  {#if showPrivilegeWarning}
    <div class="privilege-warning">
      <span class="warning-icon">\u26A0</span>
      <span>{selectedScanType?.label} requires administrator privileges. The scan may fail.</span>
    </div>
  {/if}
  <ScanActions />
</section>

<style>
  .config-panel {
    background: var(--bg-surface);
    border-radius: var(--radius-md);
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
  }

  .config-grid {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .config-row {
    display: flex;
    gap: var(--space-sm);
    flex-wrap: wrap;
  }

  .privilege-warning {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: var(--space-xs) var(--space-sm);
    background: rgba(255, 201, 77, 0.1);
    border: 1px solid var(--status-warning);
    border-radius: var(--radius-sm);
    color: var(--status-warning);
    font-size: 12px;
  }

  .warning-icon {
    font-size: 14px;
    flex-shrink: 0;
  }
</style>
