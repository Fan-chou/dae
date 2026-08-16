import { mergeSrcMacHints, type SrcMacHint } from "@/lib/format";

const storageKey = "kdae-ui-src-mac";

export function loadSrcMacHints(): SrcMacHint[] {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "[]") as unknown;
    if (!Array.isArray(saved)) return [];
    const rows: SrcMacHint[] = [];
    for (const item of saved) {
      if (!item || typeof item !== "object") continue;
      const src = String((item as SrcMacHint).src || "").trim();
      if (!src) continue;
      const mac = String((item as SrcMacHint).mac || "").trim().toLowerCase();
      rows.push(mac ? { src, mac } : { src });
    }
    return mergeSrcMacHints([], rows);
  } catch {
    return [];
  }
}

export function saveSrcMacHints(hints: SrcMacHint[]): void {
  localStorage.setItem(storageKey, JSON.stringify(hints));
}
