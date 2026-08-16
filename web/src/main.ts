import { createApp } from "vue";
import App from "./App.vue";
import { loadPrefs } from "./api/prefs";
import { i18n } from "./i18n";
import { applyTheme } from "./lib/theme";
import { router } from "./router";
import "./style.css";

applyTheme(loadPrefs().theme);

createApp(App).use(router).use(i18n).mount("#app");
