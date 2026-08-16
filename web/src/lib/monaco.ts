import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";

type MonacoApi = typeof import("monaco-editor/esm/vs/editor/editor.api");

let loading: Promise<MonacoApi> | null = null;

export function loadMonaco(): Promise<MonacoApi> {
  if (!loading) {
    const g = globalThis as typeof globalThis & { MonacoEnvironment?: { getWorker(): Worker } };
    g.MonacoEnvironment = {
      getWorker() {
        return new editorWorker();
      },
    };
    loading = import("monaco-editor/esm/vs/editor/editor.api");
  }
  return loading;
}
