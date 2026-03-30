<template>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <h1>IMQS Auth</h1>
        <p>Sign in to continue</p>
      </div>

      <form @submit.prevent="handleSubmit" novalidate>
        <div class="form-group">
          <label for="identity">Username / Email</label>
          <input
            id="identity"
            v-model="identity"
            type="text"
            autocomplete="username"
            placeholder="user@example.com"
            :disabled="loading"
            required
          />
        </div>

        <div class="form-group">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="••••••••"
            :disabled="loading"
            required
          />
        </div>

        <p v-if="errorMsg" class="error-msg" role="alert">{{ errorMsg }}</p>

        <button type="submit" class="btn-primary" :disabled="loading || !identity || !password">
          <span v-if="loading">Signing in…</span>
          <span v-else>Sign In</span>
        </button>

        <div v-if="oauthProviders.length > 0" class="oauth-divider">
          <span>or</span>
        </div>

        <div v-for="provider in oauthProvidersWithRedirect" :key="provider.Name" class="oauth-provider">
          <a :href="provider.LoginURL" class="btn-oauth">
            Sign in with {{ provider.Name }}
          </a>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { doLogin } from '../composables/useSession';
import { getOAuthProviders } from '../services/api';
import type { OAuthProvider } from '../services/types';

const emit = defineEmits<{ (e: 'logged-in'): void }>();

const identity       = ref('');
const password       = ref('');
const errorMsg       = ref('');
const oauthProviders = ref<OAuthProvider[]>([]);
const loading        = ref(false);

// Read ?redirect= (or legacy ?returnUrl=) from the current URL.
// Only allow same-host URLs to prevent open-redirect attacks.
// We compare hostname (not full origin) because the SPA is served on a
// different port (2003) than the main app (80/443).
function safeRedirectTarget(): string | null {
  const params = new URLSearchParams(window.location.search);
  const target = params.get('redirect') ?? params.get('returnUrl') ?? '';
  if (!target) return null;
  try {
    const url = new URL(target, window.location.origin);
    // Allow any port on the same hostname
    if (url.hostname !== window.location.hostname) {
      console.warn('[auth] Ignoring cross-host redirect:', target);
      return null;
    }
    console.info('[auth] Redirect after login:', url.href);
    return url.href;
  } catch {
    console.warn('[auth] Invalid redirect param:', target);
    return null;
  }
}

const redirectTarget = safeRedirectTarget();

// Append the redirect param to OAuth provider URLs so they land back correctly
const oauthProvidersWithRedirect = computed(() =>
  oauthProviders.value.map(p => ({
    ...p,
    LoginURL: redirectTarget
      ? `${p.LoginURL}${p.LoginURL.includes('?') ? '&' : '?'}redirect=${encodeURIComponent(redirectTarget)}`
      : p.LoginURL,
  }))
);

onMounted(async () => {
  try {
    oauthProviders.value = await getOAuthProviders();
  } catch { /* OAuth not configured */ }
});

async function handleSubmit() {
  if (!identity.value || !password.value) return;
  errorMsg.value = '';
  loading.value  = true;
  try {
    await doLogin(identity.value, password.value);
    if (redirectTarget) {
      window.location.href = redirectTarget;
    } else {
      emit('logged-in');
    }
  } catch (e: unknown) {
    errorMsg.value = e instanceof Error ? e.message : 'Login failed. Please try again.';
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: #f0f2f5;
}
.login-card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 16px rgba(0,0,0,0.12);
  padding: 2.5rem 2rem;
  width: 100%;
  max-width: 380px;
}
.login-header { text-align: center; margin-bottom: 2rem; }
.login-header h1 { margin: 0; font-size: 1.6rem; color: #1a73e8; }
.login-header p  { margin: 0.4rem 0 0; color: #666; font-size: 0.9rem; }
.form-group { margin-bottom: 1.1rem; }
.form-group label { display: block; margin-bottom: 0.35rem; font-size: 0.85rem; font-weight: 600; color: #444; }
.form-group input {
  width: 100%; box-sizing: border-box;
  padding: 0.55rem 0.75rem; border: 1px solid #ccc;
  border-radius: 4px; font-size: 0.95rem;
}
.form-group input:focus { outline: none; border-color: #1a73e8; box-shadow: 0 0 0 2px rgba(26,115,232,.2); }
.error-msg { color: #c0392b; font-size: 0.85rem; margin: -0.5rem 0 0.9rem; }
.btn-primary {
  width: 100%; padding: 0.65rem; background: #1a73e8;
  color: white; border: none; border-radius: 4px;
  font-size: 1rem; cursor: pointer; font-weight: 600;
}
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
.oauth-divider { text-align: center; margin: 1.2rem 0 0.8rem; color: #999; font-size: 0.85rem;
  display: flex; align-items: center; gap: 0.5rem; }
.oauth-divider::before, .oauth-divider::after { content: ''; flex: 1; height: 1px; background: #e0e0e0; }
.btn-oauth {
  display: block; width: 100%; box-sizing: border-box;
  text-align: center; padding: 0.55rem; border: 1px solid #ccc;
  border-radius: 4px; text-decoration: none; color: #333; font-size: 0.9rem;
}
.btn-oauth:hover { background: #f5f5f5; }
</style>

