<script lang="ts">
  import ScanHistory from "../history/ScanHistory.svelte";
</script>

<aside class="sidebar">
  <div class="sidebar-header">
    <h1 class="logo">RustMap</h1>
  </div>
  <ScanHistory />
</aside>

<style>
  .sidebar {
    background: var(--bg-surface);
    border-right: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .sidebar-header {
    padding: var(--space-md);
    border-bottom: 1px solid var(--border-subtle);
  }

  .logo {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
  }
</style>
