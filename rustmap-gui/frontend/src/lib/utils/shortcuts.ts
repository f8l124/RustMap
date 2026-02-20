export interface Shortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  label: string;
  description: string;
  action: () => void;
}

const registry: Shortcut[] = [];

export function registerShortcut(shortcut: Shortcut): () => void {
  registry.push(shortcut);
  return () => {
    const idx = registry.indexOf(shortcut);
    if (idx >= 0) registry.splice(idx, 1);
  };
}

export function handleGlobalKeydown(event: KeyboardEvent): void {
  // Don't trigger shortcuts when typing in input fields
  const tag = (event.target as HTMLElement)?.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    // Allow Escape to work even in inputs
    if (event.key !== "Escape") return;
  }

  for (const shortcut of registry) {
    const ctrlMatch = shortcut.ctrl ? (event.ctrlKey || event.metaKey) : !(event.ctrlKey || event.metaKey);
    const shiftMatch = shortcut.shift ? event.shiftKey : !event.shiftKey;
    const altMatch = shortcut.alt ? event.altKey : !event.altKey;

    if (event.key === shortcut.key && ctrlMatch && shiftMatch && altMatch) {
      event.preventDefault();
      shortcut.action();
      return;
    }
  }
}

export function getRegisteredShortcuts(): ReadonlyArray<Shortcut> {
  return registry;
}

export function formatShortcutKey(shortcut: Shortcut): string {
  const parts: string[] = [];
  if (shortcut.ctrl) parts.push("Ctrl");
  if (shortcut.shift) parts.push("Shift");
  if (shortcut.alt) parts.push("Alt");
  parts.push(shortcut.label);
  return parts.join("+");
}
