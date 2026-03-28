<template>
  <Teleport to="body">
    <transition name="toast">
      <div v-if="visible" class="toast" :class="'toast--' + type" role="alert">
        <span class="toast-icon">{{ icon }}</span>
        <div class="toast-body">
          <strong v-if="title">{{ title }}</strong>
          <span v-if="message"> {{ message }}</span>
        </div>
        <button class="toast-close" @click="dismiss" aria-label="Close">✕</button>
      </div>
    </transition>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';

const props = withDefaults(defineProps<{
  visible: boolean;
  title?: string;
  message?: string;
  type?: 'success' | 'error' | 'info';
  duration?: number;
}>(), {
  type:     'info',
  duration: 3500,
});

const emit = defineEmits<{ (e: 'dismiss'): void }>();

const icon = computed(() => ({ success: '✓', error: '✗', info: 'ℹ' }[props.type] ?? 'ℹ'));

let timer: ReturnType<typeof setTimeout>;
watch(() => props.visible, (v) => {
  clearTimeout(timer);
  if (v && props.duration > 0) timer = setTimeout(() => emit('dismiss'), props.duration);
});
onUnmounted(() => clearTimeout(timer));

function dismiss() { emit('dismiss'); }
</script>

<style scoped>
.toast {
  position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 10000;
  display: flex; align-items: flex-start; gap: .75rem;
  padding: .85rem 1rem; border-radius: 6px; min-width: 260px; max-width: 400px;
  box-shadow: 0 3px 12px rgba(0,0,0,.18); color: white;
}
.toast--success { background: #2e7d32; }
.toast--error   { background: #c62828; }
.toast--info    { background: #1565c0; }
.toast-icon     { font-size: 1.2rem; line-height: 1; }
.toast-body     { flex: 1; font-size: .875rem; line-height: 1.4; }
.toast-close    { background: none; border: none; color: rgba(255,255,255,.8); cursor: pointer; font-size: 1rem; padding: 0; }
.toast-enter-active, .toast-leave-active { transition: all .25s ease; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateY(.75rem); }
</style>

