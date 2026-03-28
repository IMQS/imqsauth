// ─── Auth model composable ────────────────────────────────────────────────────

import { ref, readonly } from 'vue';
import { Model } from '../services/auth';
import { applyDynamicPermissions, loadStaticPermissions } from '../services/permissions';
import * as api from '../services/api';

const model    = ref<Model | null>(null);
const loading  = ref(false);
const error    = ref<string | null>(null);

export async function refreshModel(): Promise<void> {
  loading.value = true;
  error.value   = null;
  try {
    // 1. Load the full static PermissionsTable from the server (hundreds of entries).
    try {
      const table = await api.getGroupsPermNames();
      loadStaticPermissions(table);
    } catch { /* non-fatal */ }

    // 2. Apply config-driven dynamic/disable/relabel overrides on top.
    try {
      const dynPerms = await api.getDynamicPermissions();
      applyDynamicPermissions(dynPerms);
    } catch { /* non-fatal */ }

    const m = new Model();
    await m.build();
    model.value = m;
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : 'Failed to load auth data';
    throw e;
  } finally {
    loading.value = false;
  }
}

export function clearModel(): void {
  model.value   = null;
  error.value   = null;
  loading.value = false;
}

export function useAuthModel() {
  return {
    model,           // plain Ref<Model|null> — not DeepReadonly
    loading: readonly(loading),
    error:   readonly(error),
    refresh: refreshModel,
  };
}
