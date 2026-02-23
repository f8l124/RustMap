import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

class UpdaterStore {
  available = $state(false);
  version = $state<string | null>(null);
  downloading = $state(false);
  error = $state<string | null>(null);
  private update: Update | null = null;

  async checkForUpdates() {
    try {
      this.error = null;
      const result = await check();
      if (result) {
        this.available = true;
        this.version = result.version;
        this.update = result;
      }
    } catch (e) {
      // Silently ignore update check failures (no internet, no pubkey, etc.)
      console.debug("Update check failed:", e);
    }
  }

  async downloadAndInstall() {
    if (!this.update) return;
    this.downloading = true;
    this.error = null;
    try {
      await this.update.downloadAndInstall();
      await relaunch();
    } catch (e) {
      this.error = String(e);
      this.downloading = false;
    }
  }

  dismiss() {
    this.available = false;
    this.version = null;
    this.update = null;
  }
}

export const updater = new UpdaterStore();
