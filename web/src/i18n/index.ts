import { createI18n } from "vue-i18n";

export const i18n = createI18n({
  legacy: false,
  locale: "zh-CN",
  messages: {
    "zh-CN": {
      brand: "kdae",
      nav: {
        overview: "概览",
        groups: "代理组",
        connections: "连接",
        logs: "日志",
        config: "配置",
        settings: "设置",
        reload: "热重载",
      },
      connections: {
        empty: "暂无 kdae 抓住的流。must_direct 未劫持、block 静默丢、DNS 不在此表。",
        note: "start 是 kdae 开始跟踪这条流的时间。时长由 start 推算。这是 tproxy 抓住的流，不是整机 conntrack。页隐藏时暂停轮询。",
      },
      config: {
        note: "只编辑 config.dae 的 global+routing 和 routing.dae。不会打开 nodes.dae。保存和热重载都会先 validate，失败则报错、不写坏盘、不重载。admin_secret 显示为占位符，提交时保留磁盘原值。",
      },
    },
  },
});
