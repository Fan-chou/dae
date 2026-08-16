<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import { usePreferredDark } from "@vueuse/core";
import "monaco-editor/min/vs/editor/editor.main.css";
import { DAE_LANGUAGE_ID, registerDaeLanguage } from "@/lib/dae-lang";
import { lintDae, type DaeLintKind } from "@/lib/dae-lint";
import { loadMonaco } from "@/lib/monaco";
import { resolveTheme } from "@/lib/theme";
import { ui } from "@/store/session";

const props = defineProps<{
  modelValue: string;
  kind: DaeLintKind;
}>();
const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const host = ref<HTMLDivElement | null>(null);
const prefersDark = usePreferredDark();
let editor: import("monaco-editor").editor.IStandaloneCodeEditor | null = null;
let monacoApi: typeof import("monaco-editor") | null = null;

function monacoTheme(): "vs" | "vs-dark" {
  return resolveTheme(ui.prefs.theme) === "dark" ? "vs-dark" : "vs";
}

function applyMarkers(value: string): void {
  if (!editor || !monacoApi) return;
  const model = editor.getModel();
  if (!model) return;
  const markers = lintDae(value, props.kind).map((issue) => ({
    severity: issue.severity === "warning" ? monacoApi!.MarkerSeverity.Warning : monacoApi!.MarkerSeverity.Error,
    startLineNumber: issue.line,
    startColumn: issue.column,
    endLineNumber: issue.endLine,
    endColumn: issue.endColumn,
    message: issue.message,
    source: "dae",
  }));
  monacoApi.editor.setModelMarkers(model, "dae", markers);
}

onMounted(async () => {
  const monaco = await loadMonaco();
  monacoApi = monaco;
  registerDaeLanguage(monaco);
  if (!host.value) return;
  editor = monaco.editor.create(host.value, {
    value: props.modelValue || "",
    language: DAE_LANGUAGE_ID,
    theme: monacoTheme(),
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 14,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    fontWeight: "600",
    lineHeight: 22,
    tabSize: 2,
    insertSpaces: true,
    scrollBeyondLastLine: false,
    wordWrap: "on",
    renderWhitespace: "selection",
    cursorBlinking: "solid",
    formatOnPaste: true,
    padding: { top: 8, bottom: 8 },
    smoothScrolling: true,
  });
  editor.onDidChangeModelContent(() => {
    const value = editor?.getValue() || "";
    emit("update:modelValue", value);
    applyMarkers(value);
  });
  applyMarkers(props.modelValue || "");
});

watch(
  () => props.modelValue,
  (value) => {
    if (editor && value !== editor.getValue()) {
      editor.setValue(value || "");
      applyMarkers(value || "");
    }
  },
);

watch(
  () => props.kind,
  () => {
    applyMarkers(editor?.getValue() || props.modelValue || "");
  },
);

watch(
  [() => ui.prefs.theme, prefersDark],
  () => {
    monacoApi?.editor.setTheme(monacoTheme());
  },
);

onBeforeUnmount(() => {
  editor?.dispose();
  editor = null;
});
</script>

<template>
  <div ref="host" class="h-[min(70vh,56rem)] w-full overflow-hidden rounded-box border border-base-300" />
</template>
