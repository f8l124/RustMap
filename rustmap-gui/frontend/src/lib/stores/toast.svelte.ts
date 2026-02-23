export type ToastType = "success" | "error" | "info" | "warning";

export interface Toast {
  id: number;
  message: string;
  type: ToastType;
}

let nextId = 0;

class ToastStore {
  toasts = $state<Toast[]>([]);

  add(message: string, type: ToastType = "info", durationMs = 5000) {
    const id = nextId++;
    this.toasts.push({ id, message, type });
    if (durationMs > 0) {
      setTimeout(() => this.dismiss(id), durationMs);
    }
  }

  dismiss(id: number) {
    this.toasts = this.toasts.filter((t) => t.id !== id);
  }

  success(message: string) {
    this.add(message, "success");
  }

  error(message: string) {
    this.add(message, "error", 8000);
  }

  warn(message: string) {
    this.add(message, "warning");
  }

  info(message: string) {
    this.add(message, "info");
  }
}

export const toasts = new ToastStore();
