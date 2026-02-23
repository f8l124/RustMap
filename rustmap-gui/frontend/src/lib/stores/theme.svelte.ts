type Theme = "dark" | "light";

const STORAGE_KEY = "rustmap-theme";

class ThemeStore {
  current = $state<Theme>("dark");

  constructor() {
    const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
    this.current = stored === "light" ? "light" : "dark";
    this.apply();
  }

  toggle() {
    this.current = this.current === "dark" ? "light" : "dark";
    localStorage.setItem(STORAGE_KEY, this.current);
    this.apply();
  }

  private apply() {
    document.documentElement.setAttribute("data-theme", this.current);
  }
}

export const theme = new ThemeStore();
