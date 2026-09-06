import { inject, nextTick, provide, type InjectionKey } from 'vue'

/*
 * 虚拟列表里某一行改高度，后面所有行的 top 都要 JS 重算一遍再 patch 回 DOM ——
 * 折叠卡片逐帧变高的话，整列就是每帧重排一次。
 *
 * 动画期间改走这里：正在变化的卡片固定住占位高度、自己浮起来改变高度；列协调器记录
 * 每一行最终会产生的高度差，然后给后续行写入其上方所有高度差的前缀和。这样同列多个组
 * 一起展开 / 收起时也只改 transform，不会互相打断后退回逐帧重排。
 *
 * 一批动画全部结束后再一起释放占位并同步真实高度给 virtualizer。下一次 Vue patch 里
 * virtualizer 的 top 和这里撤掉的 transform 正好抵消，因此收尾也不会跳。
 */
export type VirtualRowShift = {
  begin: (row: HTMLElement, release: () => void) => void
  update: (row: HTMLElement, offset: number) => void
  end: (row: HTMLElement) => void
  cancel: (row: HTMLElement) => void
  destroy: () => void
}

type RowShiftState = {
  offset: number
  finished: boolean
  release: () => void
}

const ROW_CLASS = 'virtual-row-shift-row'
const SHIFT_VAR = '--virtual-row-shift'

const virtualRowShiftKey: InjectionKey<VirtualRowShift> = Symbol('virtual-row-shift')

export const provideVirtualRowShift = (shift: VirtualRowShift) => {
  provide(virtualRowShiftKey, shift)
}

export const useVirtualRowShift = () => inject(virtualRowShiftKey, null)

export const createVirtualRowShift = (
  getColumn: () => HTMLElement | undefined,
  measureRow: (row: HTMLElement) => void,
): VirtualRowShift => {
  const shifts = new Map<HTMLElement, RowShiftState>()
  let observer: MutationObserver | undefined
  let observedColumn: HTMLElement | undefined
  let settling = false

  const clearRowStyle = (row: HTMLElement) => {
    row.classList.remove(ROW_CLASS)
    row.style.removeProperty(SHIFT_VAR)
  }

  /*
   * 每个已挂载行的位移 = 它上方所有动画行的目标高度差之和。动画 origin 自己也要吃到
   * 更早 origin 的位移，所以先给当前行写前缀和，再把当前行的差值累加进去。
   */
  const applyOffsets = () => {
    const column = getColumn()

    if (!column) return

    let offset = 0
    let followsOrigin = false

    for (const child of column.children) {
      const row = child as HTMLElement

      if (followsOrigin) {
        row.classList.add(ROW_CLASS)
        row.style.setProperty(SHIFT_VAR, `${offset}px`)
      } else {
        clearRowStyle(row)
      }

      const state = shifts.get(row)

      if (state) {
        followsOrigin = true
        offset += state.offset
      }
    }
  }

  // 动画中滚动会让 virtualizer 换一批 DOM 行，新挂载的行也要立刻拿到正确的前缀和。
  const observeColumn = () => {
    const column = getColumn()

    if (!column || column === observedColumn) return

    observer?.disconnect()
    observedColumn = column
    observer = new MutationObserver(applyOffsets)
    observer.observe(column, { childList: true })
  }

  const stopObservingColumn = () => {
    observer?.disconnect()
    observer = undefined
    observedColumn = undefined
  }

  const releaseAll = () => {
    if (!shifts.size || settling) return

    settling = true

    for (const state of shifts.values()) {
      state.release()
    }

    for (const row of shifts.keys()) {
      if (row.isConnected) {
        measureRow(row)
      }
    }

    /*
     * measureRow 会同步更新 virtualizer 数据，DOM 的 top 在下一次 Vue patch 落下。等同一个
     * nextTick 再撤 transform，二者在一次绘制前完成，视觉位置保持不变。
     */
    nextTick(() => {
      shifts.clear()
      applyOffsets()
      stopObservingColumn()
      settling = false
    })
  }

  const shift: VirtualRowShift = {
    begin: (row, release) => {
      observeColumn()

      const state = shifts.get(row)

      if (state) {
        state.finished = false
        state.release = release
      } else {
        shifts.set(row, { offset: 0, finished: false, release })
      }

      applyOffsets()
    },
    update: (row, offset) => {
      const state = shifts.get(row)

      if (!state) return

      state.offset = offset
      state.finished = false
      applyOffsets()
    },
    end: (row) => {
      const state = shifts.get(row)

      if (!state) return

      state.finished = true

      if ([...shifts.values()].every((item) => item.finished)) {
        releaseAll()
      }
    },
    /*
     * 行在动画中被卸载时不能继续等同批的其他行，否则已经不存在的占位无法在批末测量。
     * 此时整批提前落位；这是滚动 / 过滤时的低频兜底，正常的并发展开仍走批量收尾。
     */
    cancel: (row) => {
      const state = shifts.get(row)

      if (!state) return

      releaseAll()
    },
    destroy: () => {
      stopObservingColumn()

      for (const state of shifts.values()) {
        state.release()
      }

      shifts.clear()

      const column = getColumn()

      if (column) {
        for (const child of column.children) {
          clearRowStyle(child as HTMLElement)
        }
      }
    },
  }

  return shift
}
