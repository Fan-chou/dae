<script setup lang="ts">

const paths = {
  overview: "m3 10 9-7 9 7M5 9v12h5v-7h4v7h5V9",
  groups: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8M5 21v-2a7 7 0 0 1 14 0v2M3 8a3 3 0 0 0 0 6M21 8a3 3 0 0 1 0 6",
  connections: "M4 7h16m-5-4 5 4-5 4M20 17H4m5-4-5 4 5 4",
  logs: "M5 3h9l5 5v13H5zM14 3v5h5M8 12h8M8 16h6",
  config: "M4 3h10v18H4zM14 8l6 3v10h-6M7 7h4M7 11h4M7 15h4",
  settings: "M3 6h8m4 0h6M3 12h2m4 0h12M3 18h12m4 0h2M11 3v6M5 9v6M15 15v6",
  chevron: "m9 5 7 7-7 7",

  sun: "M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0",
  moon: "M20 15.5A9 9 0 0 1 8.5 4 9 9 0 1 0 20 15.5",
  pause: "M8 5v14M16 5v14", play: "m8 5 11 7-11 7z",
  refresh: "M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-1l2 6M4 12l2 6a7 7 0 0 0 12-1",
  close: "m6 6 12 12M6 18 18 6", copy: "M9 9h11v11H9zM15 5V2H2v13h3",
  filter: "M4 6h16M7 12h10M10 18h4", up: "m6 10 6-6 6 6M12 4v16",
  down: "m6 14 6 6 6-6M12 4v16", search: "m16 16 5 5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
};
defineProps<{ name: keyof typeof paths }>();
</script>
<template><svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path :d="paths[name]" /></svg></template>
