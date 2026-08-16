import { useMediaQuery } from "@vueuse/core";
import type { ConnViewMode } from "@/api/prefs";

export function useCompactLayout() {
  return useMediaQuery("(max-width: 767px)");
}

export function effectiveConnView(pref: ConnViewMode, compact: boolean): "table" | "card" {
  if (pref === "card") return "card";
  if (pref === "table") return "table";
  return compact ? "card" : "table";
}
