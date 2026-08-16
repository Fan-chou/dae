const storageKey = "kdae-ui-settings";

export type UiSettings = {
  baseUrl: string;
  secret: string;
};

export function defaultBaseUrl(): string {
  if (typeof location === "undefined") {
    return "/cgi-bin/kdae-proxy";
  }
  if (location.protocol === "https:" || location.pathname.indexOf("/kdae-ui") === 0) {
    return location.origin + "/cgi-bin/kdae-proxy";
  }
  if (location.hostname === "127.0.0.1" || location.hostname === "localhost") {
    return "";
  }
  return "http://192.168.124.223:2025";
}

export function loadSettings(): UiSettings {
  const defaults: UiSettings = { baseUrl: defaultBaseUrl(), secret: "" };
  try {
    const saved = Object.assign({}, defaults, JSON.parse(localStorage.getItem(storageKey) || "{}")) as UiSettings;
    if (typeof location !== "undefined" && location.protocol === "https:" && /^http:\/\//.test(saved.baseUrl || "")) {
      saved.baseUrl = defaultBaseUrl();
    }
    return saved;
  } catch {
    return defaults;
  }
}

export function saveSettings(settings: UiSettings): void {
  localStorage.setItem(storageKey, JSON.stringify(settings));
}

export function apiUrl(baseUrl: string, path: string): string {
  return String(baseUrl || "").replace(/\/$/, "") + path;
}
