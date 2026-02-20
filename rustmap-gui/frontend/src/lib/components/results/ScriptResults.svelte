<script lang="ts">
  import type { ScriptResult } from "../../types";

  interface Props {
    scripts: ScriptResult[];
  }

  let { scripts }: Props = $props();
</script>

{#if scripts.length > 0}
  <div class="script-results">
    {#each scripts as script}
      <div class="script">
        <span class="script-id mono">{script.id}:</span>
        <pre class="script-output mono">{script.output}</pre>
      </div>
    {/each}
  </div>
{/if}

<style>
  .script-results {
    display: flex;
    flex-direction: column;
    gap: var(--space-xs);
  }

  .script {
    font-size: 12px;
  }

  .script-id {
    color: var(--accent);
    font-weight: 600;
  }

  .script-output {
    margin: var(--space-xs) 0 0 var(--space-md);
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--text-secondary);
    font-size: 12px;
  }
</style>
