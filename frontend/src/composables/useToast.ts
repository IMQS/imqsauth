// ─── Global toast notification composable ────────────────────────────────────
import { reactive } from 'vue';

interface ToastState {
  visible: boolean;
  title: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

export const toast = reactive<ToastState>({
  visible: false,
  title: '',
  message: '',
  type: 'info',
});

export function showToast(title: string, message = '', type: ToastState['type'] = 'info') {
  toast.title   = title;
  toast.message = message;
  toast.type    = type;
  toast.visible = true;
}

export function dismissToast() {
  toast.visible = false;
}

