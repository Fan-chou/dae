import { createI18n } from "vue-i18n";

export const i18n = createI18n({
  legacy: false,
  locale: "zh-CN",
  messages: {
    "zh-CN": {
      brand: "kdae",
      nav: {
        overview: "概览",
        groups: "组",
        connections: "连接",
        logs: "日志",
        config: "配置",
        settings: "设置",
        reload: "热重载",
      },
      connections: {
        empty: "连接表将在 API 就绪后显示 kdae 抓住的流，不是整机 conntrack。",
        note: "must_direct 未劫持、block 静默丢、DNS 不在此表。",
      },
      config: {
        placeholder: "配置编辑在后续步骤开放。此处不打开 nodes.dae。",
      },
    },
  },
});
