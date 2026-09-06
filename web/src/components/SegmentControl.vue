<script setup lang="ts">
const props = defineProps<{ modelValue: string; options: readonly {value:string; label:string; count?:number}[]; label:string }>();
const emit = defineEmits<{ "update:modelValue": [value:string] }>();
function move(event: KeyboardEvent, index: number): void {
  if (!["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) return;
  event.preventDefault();
  const next = event.key === "Home" ? 0 : event.key === "End" ? props.options.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + props.options.length) % props.options.length;
  emit("update:modelValue", props.options[next]!.value);
  ((event.currentTarget as HTMLElement).parentElement?.children[next] as HTMLElement)?.focus();
}
</script>
<template><div class="segment-control" role="group" :aria-label="label"><button v-for="(option,index) in options" :key="option.value" :aria-pressed="modelValue === option.value" :tabindex="modelValue === option.value ? 0 : -1" @click="emit('update:modelValue',option.value)" @keydown="move($event,index)">{{ option.label }}<span v-if="option.count != null"> ({{ option.count }})</span></button></div></template>
