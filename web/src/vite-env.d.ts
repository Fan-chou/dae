/// <reference types="vite/client" />

declare module "*.vue" {
  import type { DefineComponent } from "vue";
  const component: DefineComponent<object, object, unknown>;
  export default component;
}

declare module "*?worker" {
  const worker: {
    new (): Worker;
  };
  export default worker;
}
