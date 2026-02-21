<script lang="ts">
  import { scanConfig } from "../../stores/scanConfig.svelte";
  import {
    listScripts,
    parseCustomScripts,
    getScriptsDir,
  } from "../../tauri/commands";
  import { open } from "@tauri-apps/plugin-dialog";
  import Collapsible from "../shared/Collapsible.svelte";
  import Toggle from "../shared/Toggle.svelte";
  import type { ScriptInfo } from "../../types";

  let allScripts = $state<ScriptInfo[]>([]);
  let loading = $state(false);
  let loadError = $state("");
  let searchQuery = $state("");
  let patternInput = $state("");
  // Plain (non-reactive) flag to prevent the $effect from re-triggering
  // loadScripts when allScripts changes. Using $state here would cause
  // an infinite loop when listScripts() returns an empty array.
  let scriptsLoaded = false;

  // Custom (user-browsed) scripts: maps file path → parsed metadata
  let customScripts = $state<Map<string, ScriptInfo>>(new Map());
  let browseError = $state("");

  const CATEGORY_PRESETS = ["default", "safe", "discovery", "version", "auth"];

  const filteredScripts = $derived(
    searchQuery.trim()
      ? allScripts.filter(
          (s) =>
            s.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
            s.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
            s.categories.some((c) =>
              c.toLowerCase().includes(searchQuery.toLowerCase()),
            ),
        )
      : allScripts,
  );

  const selectedCount = $derived(
    scanConfig.scripts.length + scanConfig.customScriptPaths.length,
  );

  async function loadScripts() {
    if (scriptsLoaded) return;
    scriptsLoaded = true;
    loading = true;
    loadError = "";
    try {
      allScripts = await listScripts();
    } catch (e) {
      loadError = String(e);
    } finally {
      loading = false;
    }
  }

  function toggleScript(id: string) {
    const idx = scanConfig.scripts.indexOf(id);
    if (idx >= 0) {
      scanConfig.scripts = scanConfig.scripts.filter((s) => s !== id);
    } else {
      scanConfig.scripts = [...scanConfig.scripts, id];
    }
  }

  function selectCategory(category: string) {
    const matching = allScripts
      .filter((s) => s.categories.includes(category))
      .map((s) => s.id);
    const existing = new Set(scanConfig.scripts);
    const allSelected = matching.every((id) => existing.has(id));
    if (allSelected) {
      // Deselect all in this category
      scanConfig.scripts = scanConfig.scripts.filter(
        (s) => !matching.includes(s),
      );
    } else {
      // Select all in this category
      for (const id of matching) {
        existing.add(id);
      }
      scanConfig.scripts = [...existing];
    }
  }

  function addPattern() {
    const p = patternInput.trim();
    if (p && !scanConfig.scripts.includes(p)) {
      scanConfig.scripts = [...scanConfig.scripts, p];
    }
    patternInput = "";
  }

  function removeScript(id: string) {
    scanConfig.scripts = scanConfig.scripts.filter((s) => s !== id);
  }

  function selectAll() {
    scanConfig.scripts = allScripts.map((s) => s.id);
  }

  function selectNone() {
    scanConfig.scripts = [];
  }

  function categoryBadgeVariant(
    cat: string,
  ): "success" | "error" | "warning" | "info" | "muted" {
    switch (cat) {
      case "safe":
        return "success";
      case "intrusive":
      case "exploit":
      case "dos":
        return "error";
      case "default":
        return "info";
      case "discovery":
      case "version":
        return "warning";
      default:
        return "muted";
    }
  }

  function langIcon(lang: string): string {
    switch (lang) {
      case "lua":
        return "Lua";
      case "python":
        return "Py";
      case "wasm":
        return "Wasm";
      default:
        return lang;
    }
  }

  async function browseScripts() {
    browseError = "";
    try {
      const defaultPath = (await getScriptsDir()) ?? undefined;
      const selected = await open({
        multiple: true,
        defaultPath,
        filters: [
          {
            name: "Scripts",
            extensions: ["lua", "py", "wasm"],
          },
        ],
        title: "Select Script Files",
      });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      // Filter out already-added paths
      const newPaths = paths.filter(
        (p) => !scanConfig.customScriptPaths.includes(p),
      );
      if (newPaths.length === 0) return;
      // Parse metadata from the backend
      const infos = await parseCustomScripts(newPaths);
      const updated = new Map(customScripts);
      for (let i = 0; i < newPaths.length; i++) {
        updated.set(newPaths[i], infos[i]);
      }
      customScripts = updated;
      scanConfig.customScriptPaths = [
        ...scanConfig.customScriptPaths,
        ...newPaths,
      ];
    } catch (e) {
      browseError = String(e);
    }
  }

  function removeCustomScript(path: string) {
    scanConfig.customScriptPaths = scanConfig.customScriptPaths.filter(
      (p) => p !== path,
    );
    const updated = new Map(customScripts);
    updated.delete(path);
    customScripts = updated;
  }

  $effect(() => {
    if (scanConfig.scriptEnabled) {
      loadScripts();
    }
  });
</script>

<Collapsible title="Scripts (NSE)">
  <div class="script-config">
    <div class="script-toggle-row">
      <Toggle
        label="Enable Scripts (--script)"
        bind:checked={scanConfig.scriptEnabled}
      />
      {#if selectedCount > 0}
        <span class="selected-count">{selectedCount} selected</span>
      {/if}
    </div>

    {#if scanConfig.scriptEnabled}
      {#if loading}
        <div class="loading">Loading scripts...</div>
      {:else if loadError}
        <div class="error">Failed to load scripts: {loadError}</div>
      {:else}
        <!-- Category quick-select -->
        <div class="categories">
          <span class="section-label">Categories:</span>
          {#each CATEGORY_PRESETS as cat}
            <button
              class="category-btn"
              class:active={allScripts
                .filter((s) => s.categories.includes(cat))
                .every((s) => scanConfig.scripts.includes(s.id))}
              onclick={() => selectCategory(cat)}
            >
              {cat}
            </button>
          {/each}
          <button class="category-btn select-action" onclick={selectAll}
            >All</button
          >
          <button class="category-btn select-action" onclick={selectNone}
            >None</button
          >
        </div>

        <!-- Pattern input + Browse -->
        <div class="pattern-row">
          <input
            class="input pattern-input"
            type="text"
            placeholder="Add pattern (e.g. http-*, smb-*)"
            bind:value={patternInput}
            onkeydown={(e) => {
              if (e.key === "Enter") addPattern();
            }}
          />
          <button class="add-btn" onclick={addPattern} disabled={!patternInput.trim()}>Add</button>
          <button class="browse-btn" onclick={browseScripts}>Browse...</button>
        </div>
        {#if browseError}
          <div class="error">{browseError}</div>
        {/if}

        <!-- Custom (user-browsed) scripts -->
        {#if scanConfig.customScriptPaths.length > 0}
          <div class="custom-scripts-section">
            <span class="section-label">Custom Scripts:</span>
            <div class="custom-script-list">
              {#each scanConfig.customScriptPaths as path}
                {@const info = customScripts.get(path)}
                <div class="custom-script-item">
                  <div class="custom-script-info">
                    <span class="script-id">{info?.id ?? path.split(/[\\/]/).pop()}</span>
                    {#if info}
                      <span class="lang-badge">{langIcon(info.language)}</span>
                    {/if}
                    <span class="custom-script-path" title={path}>{path}</span>
                  </div>
                  {#if info?.description}
                    <div class="script-desc">{info.description}</div>
                  {/if}
                  <button class="tag-remove" onclick={() => removeCustomScript(path)}>&times;</button>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Selected scripts tags -->
        {#if scanConfig.scripts.length > 0}
          <div class="selected-tags">
            {#each scanConfig.scripts as script}
              <span class="tag">
                {script}
                <button class="tag-remove" onclick={() => removeScript(script)}
                  >&times;</button
                >
              </span>
            {/each}
          </div>
        {/if}

        <!-- Search -->
        <input
          class="input search-input"
          type="text"
          placeholder="Search scripts..."
          bind:value={searchQuery}
        />

        <!-- Script list -->
        <div class="script-list">
          {#each filteredScripts as script}
            <label class="script-item" class:selected={scanConfig.scripts.includes(script.id)}>
              <input
                type="checkbox"
                checked={scanConfig.scripts.includes(script.id)}
                onchange={() => toggleScript(script.id)}
              />
              <div class="script-info">
                <div class="script-header">
                  <span class="script-id">{script.id}</span>
                  <span class="lang-badge">{langIcon(script.language)}</span>
                </div>
                <div class="script-desc">{script.description}</div>
                <div class="script-cats">
                  {#each script.categories as cat}
                    <span class="cat-tag cat-{categoryBadgeVariant(cat)}"
                      >{cat}</span
                    >
                  {/each}
                </div>
              </div>
            </label>
          {/each}
          {#if filteredScripts.length === 0 && searchQuery}
            <div class="no-results">No scripts match "{searchQuery}"</div>
          {/if}
        </div>

        <!-- Script args -->
        <div class="field">
          <label for="script-args" class="label">Script Arguments</label>
          <input
            id="script-args"
            class="input"
            type="text"
            placeholder="key1=val1,key2=val2"
            bind:value={scanConfig.scriptArgs}
          />
        </div>
      {/if}
    {/if}
  </div>
</Collapsible>

<style>
  .script-config {
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
  }

  .script-toggle-row {
    display: flex;
    align-items: center;
    gap: var(--space-md);
  }

  .selected-count {
    font-size: 11px;
    color: var(--accent);
    font-weight: 600;
  }

  .loading,
  .error {
    font-size: 12px;
    padding: var(--space-sm);
  }

  .loading {
    color: var(--text-muted);
  }

  .error {
    color: var(--port-closed);
  }

  .categories {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .section-label {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .category-btn {
    padding: 2px 10px;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition:
      background 0.15s,
      color 0.15s,
      border-color 0.15s;
  }

  .category-btn:hover {
    border-color: var(--accent);
    color: var(--text-primary);
  }

  .category-btn.active {
    background: rgba(79, 140, 255, 0.15);
    border-color: var(--accent);
    color: var(--accent);
  }

  .category-btn.select-action {
    border-style: dashed;
  }

  .pattern-row {
    display: flex;
    gap: var(--space-xs);
  }

  .pattern-input {
    flex: 1;
  }

  .add-btn,
  .browse-btn {
    padding: 4px 12px;
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: rgba(79, 140, 255, 0.1);
    color: var(--accent);
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .add-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .browse-btn:hover {
    background: rgba(79, 140, 255, 0.2);
  }

  .custom-scripts-section {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .custom-script-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .custom-script-item {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
    padding: 4px var(--space-sm);
    border-bottom: 1px solid var(--border-subtle);
  }

  .custom-script-item:last-child {
    border-bottom: none;
  }

  .custom-script-info {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    flex: 1;
    min-width: 0;
  }

  .custom-script-path {
    font-size: 10px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .selected-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    background: rgba(79, 140, 255, 0.12);
    border-radius: var(--radius-sm);
    font-size: 11px;
    color: var(--accent);
    font-family: var(--font-mono);
  }

  .tag-remove {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 0 2px;
    font-size: 14px;
    line-height: 1;
  }

  .tag-remove:hover {
    color: var(--port-closed);
  }

  .search-input {
    width: 100%;
  }

  .script-list {
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .script-item {
    display: flex;
    align-items: flex-start;
    gap: var(--space-sm);
    padding: 6px var(--space-sm);
    cursor: pointer;
    border-bottom: 1px solid var(--border-subtle);
    transition: background 0.1s;
  }

  .script-item:last-child {
    border-bottom: none;
  }

  .script-item:hover {
    background: rgba(255, 255, 255, 0.03);
  }

  .script-item.selected {
    background: rgba(79, 140, 255, 0.06);
  }

  .script-item input[type="checkbox"] {
    margin-top: 2px;
    flex-shrink: 0;
  }

  .script-info {
    flex: 1;
    min-width: 0;
  }

  .script-header {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
  }

  .script-id {
    font-size: 12px;
    font-weight: 600;
    font-family: var(--font-mono);
    color: var(--text-primary);
  }

  .lang-badge {
    font-size: 9px;
    padding: 0 4px;
    border-radius: 3px;
    background: rgba(108, 108, 128, 0.2);
    color: var(--text-muted);
    font-weight: 700;
    text-transform: uppercase;
  }

  .script-desc {
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .script-cats {
    display: flex;
    gap: 3px;
    margin-top: 2px;
  }

  .cat-tag {
    font-size: 9px;
    padding: 0 5px;
    border-radius: 3px;
    font-weight: 600;
  }

  .cat-success {
    background: rgba(45, 212, 168, 0.15);
    color: var(--port-open);
  }

  .cat-error {
    background: rgba(255, 92, 92, 0.15);
    color: var(--port-closed);
  }

  .cat-warning {
    background: rgba(255, 201, 77, 0.15);
    color: var(--port-filtered);
  }

  .cat-info {
    background: rgba(79, 140, 255, 0.15);
    color: var(--accent);
  }

  .cat-muted {
    background: rgba(108, 108, 128, 0.15);
    color: var(--text-muted);
  }

  .no-results {
    padding: var(--space-md);
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .label {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .input {
    padding: 6px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 13px;
    font-family: var(--font-mono);
  }

  .input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .input::placeholder {
    color: var(--text-muted);
  }
</style>
