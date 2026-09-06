import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'
import { FDAE_LANGUAGE } from './editor-language'
type Monaco = typeof import('monaco-editor/esm/vs/editor/editor.api')
let pending: Promise<Monaco> | undefined
export function loadEditor() {
  if (!pending) {
    const global = globalThis as typeof globalThis & {
      MonacoEnvironment?: { getWorker(): Worker }
    }
    global.MonacoEnvironment = { getWorker: () => new EditorWorker() }
    pending = Promise.all([
      import('monaco-editor/esm/vs/editor/editor.api'),
      import('monaco-editor/esm/vs/editor/contrib/find/browser/findController.js'),
      import('monaco-editor/esm/vs/editor/contrib/folding/browser/folding.js'),
      import('monaco-editor/esm/vs/editor/contrib/bracketMatching/browser/bracketMatching.js'),
    ])
      .then(([monaco]) => {
        monaco.languages.register({ id: 'fdae', extensions: ['.dae'] })
        monaco.languages.setMonarchTokensProvider('fdae', FDAE_LANGUAGE)
        monaco.languages.setLanguageConfiguration('fdae', {
          comments: { lineComment: '#' },
          brackets: [
            ['{', '}'],
            ['(', ')'],
            ['[', ']'],
          ],
          autoClosingPairs: [
            { open: '{', close: '}' },
            { open: '(', close: ')' },
            { open: '[', close: ']' },
            { open: '"', close: '"', notIn: ['string', 'comment'] },
            { open: "'", close: "'", notIn: ['string', 'comment'] },
          ],
        })
        return monaco
      })
      .catch((error) => {
        pending = undefined
        throw error
      })
  }
  return pending
}
