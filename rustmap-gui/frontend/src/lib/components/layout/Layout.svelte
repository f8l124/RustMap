<script lang="ts">
  import Sidebar from "./Sidebar.svelte";
  import MainPanel from "./MainPanel.svelte";
  import StatusBar from "./StatusBar.svelte";
</script>

<div class="layout">
  <Sidebar />
  <MainPanel />
  <StatusBar />
</div>

<style>
  .layout {
    display: grid;
    grid-template-columns: 260px 1fr;
    grid-template-rows: 1fr auto;
    height: 100%;
  }
</style>
