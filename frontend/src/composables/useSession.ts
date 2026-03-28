// ─── Reactive auth session store ─────────────────────────────────────────────

import { reactive, readonly } from 'vue';
import * as api from '../services/api';
import { storeSession, clearSession, isLoggedIn, isLocalAdmin } from '../services/auth';
import type { CheckResponse } from '../services/types';

interface SessionState {
  loggedIn: boolean;
  userId: string;
  identity: string;
  isAdmin: boolean;
  loading: boolean;
  error: string | null;
}

const state = reactive<SessionState>({
  loggedIn: false,
  userId: '',
  identity: '',
  isAdmin: false,
  loading: false,
  error: null,
});

function applyCheck(data: CheckResponse) {
  storeSession({ Identity: data.Identity, UserId: String(data.UserId), InternalUUID: data.InternalUUID, Roles: data.Roles });
  state.loggedIn  = true;
  state.userId    = String(data.UserId);
  state.identity  = data.Identity || data.Email || data.Username;
  state.isAdmin   = isLocalAdmin();
  state.error     = null;
}

export async function initSession(): Promise<void> {
  if (!isLoggedIn()) return;
  try {
    const data = await api.check();
    applyCheck(data);
  } catch {
    // Session cookie present but stale – clear it
    clearSession();
  }
}

export async function doLogin(identity: string, password: string): Promise<void> {
  state.loading = true;
  state.error   = null;
  try {
    const data = await api.login(identity, password);
    applyCheck(data);
  } catch (e: unknown) {
    state.error = e instanceof Error ? e.message : 'Login failed';
    throw e;
  } finally {
    state.loading = false;
  }
}

export async function doLogout(): Promise<void> {
  try { await api.logout(); } catch { /* ignore */ }
  clearSession();
  state.loggedIn  = false;
  state.userId    = '';
  state.identity  = '';
  state.isAdmin   = false;
}

export const session = readonly(state);

