<template>
  <!-- Inline confirmation dialog -->
  <Teleport to="body">
    <div v-if="visible" class="modal-overlay" role="dialog" :aria-labelledby="titleId" aria-modal="true">
      <div class="modal-box">
        <p :id="titleId" class="modal-title">{{ title }}</p>
        <p v-if="message" class="modal-message">{{ message }}</p>
        <div class="modal-actions">
          <button class="btn-neutral" @click="cancel">{{ cancelLabel }}</button>
          <button :class="'btn-' + variant" @click="confirm">{{ confirmLabel }}</button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(defineProps<{
  visible: boolean;
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'primary' | 'danger';
}>(), {
  confirmLabel: 'OK',
  cancelLabel:  'Cancel',
  variant:      'primary',
});

const emit = defineEmits<{
  (e: 'confirm'): void;
  (e: 'cancel'): void;
}>();

const titleId = computed(() => 'confirm-dialog-title-' + Math.random().toString(36).slice(2));

function confirm() { emit('confirm'); }
function cancel()  { emit('cancel'); }
</script>

<style scoped>
.modal-overlay {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(0,0,0,.4);
  display: flex; align-items: center; justify-content: center;
}
.modal-box {
  background: var(--md-surface); border-radius: var(--md-radius-md);
  box-shadow: var(--md-elevation-5);
  padding: 1.5rem 1.75rem; min-width: 300px; max-width: 440px;
}
.modal-title   { font-weight: 500; font-size: 1.125rem; margin: 0 0 .5rem; }
.modal-message { font-size: .875rem; color: var(--md-text-secondary); margin: 0 0 1.25rem; }
.modal-actions { display: flex; justify-content: flex-end; gap: .6rem; }
</style>

