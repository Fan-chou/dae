import { inject, provide, type InjectionKey, type Ref } from 'vue'

/*
 * 折叠卡片「正在展开 / 收起」的标记，给内容侧用来压低这段时间的渲染量。
 *
 * 展开时它从内容挂载那一刻就是 true —— 卡片是在动画开始之前挂好的(见 CollapseCard.vue)，
 * 所以「动画期间」实际覆盖的是挂载 + 动画这一整段。虚拟列表在这段时间里只渲一屏，
 * 屏外的几行等 transitionend 之后再补上。
 */
const collapseTransitionKey: InjectionKey<Ref<boolean>> = Symbol('collapse-transition')

export const provideCollapseTransition = (transitioning: Ref<boolean>) => {
  provide(collapseTransitionKey, transitioning)
}

export const useCollapseTransition = () => inject(collapseTransitionKey, null)
