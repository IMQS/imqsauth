<template>
  <div class="app-shell">
    <!-- Top navigation bar -->
    <header class="app-header">
      <div class="app-brand">IMQS Auth</div>
      <nav class="app-tabs" v-if="session.loggedIn && session.isAdmin">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          class="tab-btn"
          :class="{ active: activeTab === tab.id }"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
        </button>
      </nav>
      <div class="app-header-right" v-if="session.loggedIn">
        <span class="user-identity">{{ session.identity }}</span>
        <button class="btn-logout" @click="handleLogout">Sign out</button>
      </div>
    </header>

    <!-- Main content -->
    <main class="app-main">
      <!-- Login screen -->
      <LoginPage v-if="!session.loggedIn" />

      <!-- Not admin notice -->
      <div v-else-if="!session.isAdmin" class="not-admin">
        <p>You do not have administrator rights to access this page.</p>
        <button class="btn-neutral" @click="handleLogout">Sign out</button>
      </div>

      <!-- Loading state (only for the very first load - once we have a model,
           keep the tab components mounted during background refreshes so
           their local state, e.g. the selected group/user, isn't lost). -->
      <div v-else-if="modelLoading && !model" class="loading-state">
        <div class="spinner"></div>
        <span>Loading auth data…</span>
      </div>

      <!-- Error state (same reasoning - don't tear down an already-loaded
           model's views just because a background refresh failed). -->
      <div v-else-if="modelError && !model" class="error-state">
        <p>{{ modelError }}</p>
        <button class="btn-primary" @click="refreshModel">Retry</button>
      </div>

      <!-- Users tab -->
      <UserList
        v-else-if="activeTab === 'users'"
        :users="model?.users ?? []"
        :groups="model?.groups ?? []"
        :modules="modules"
        :loading="modelLoading"
        @refresh="refreshModel"
      />

      <!-- Groups tab -->
      <GroupList
        v-else-if="activeTab === 'groups'"
        :groups="model?.groups ?? []"
        :loading="modelLoading"
        @refresh="refreshModel"
      />
    </main>

    <!-- Global toast -->
    <ToastNotification
      :visible="toast.visible"
      :title="toast.title"
      :message="toast.message"
      :type="toast.type"
      @dismiss="dismissToast"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { session, initSession, doLogout } from './composables/useSession';
import { useAuthModel, clearModel }        from './composables/useAuthModel';
import { toast, dismissToast }            from './composables/useToast';
import { allModuleOptions }               from './services/modules';
import { Permissions }                    from './services/permissions';
import LoginPage          from './components/LoginPage.vue';
import UserList           from './components/UserList.vue';
import GroupList          from './components/GroupList.vue';
import ToastNotification  from './components/ToastNotification.vue';

// ── Tabs ───────────────────────────────────────────────────────────────────
const tabs = [
  { id: 'users',  label: 'Users'  },
  { id: 'groups', label: 'Groups' },
] as const;
type TabId = typeof tabs[number]['id'];

const activeTab = ref<TabId>('users');

// ── Auth model ─────────────────────────────────────────────────────────────
const { model, loading: modelLoading, error: modelError, refresh: refreshModel } = useAuthModel();

const modules = computed(() => allModuleOptions());

// ── Session ────────────────────────────────────────────────────────────────
onMounted(async () => {
  await initSession();
});

// Whenever loggedIn flips true and the user is an admin → load data.
// Whenever it flips false (logout) → clear stale data immediately.
watch(() => session.loggedIn, async (loggedIn) => {
  if (loggedIn && session.isAdmin) {
    await refreshModel().catch(() => { /* error shown in template */ });
  } else if (!loggedIn) {
    clearModel();
  }
});

async function handleLogout() {
  await doLogout();
}
</script>

<style>
/* Global resets - shared tokens/base styles now live in src/assets/material.css */
</style>

<style scoped>
.app-shell { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
.app-header {
  display: flex; align-items: center; gap: 1rem;
  background: var(--md-primary); color: white; padding: 0 1rem; height: 56px;
  flex-shrink: 0; box-shadow: var(--md-elevation-2); z-index: 1;
}
.app-brand { font-size: 1.15rem; font-weight: 500; letter-spacing: .03em; }
.app-tabs { display: flex; gap: 0; height: 100%; }
.tab-btn {
  height: 100%; padding: 0 1.1rem; background: none; border: none;
  color: rgba(255,255,255,.75); font-size: .8125rem; font-weight: 500;
  letter-spacing: .03em; text-transform: uppercase;
  cursor: pointer; border-bottom: 3px solid transparent;
  box-shadow: none;
  transition: color var(--md-motion-fast) var(--md-easing),
              background-color var(--md-motion-fast) var(--md-easing),
              border-color var(--md-motion-fast) var(--md-easing);
}
.tab-btn:hover  { color: white; background: rgba(255,255,255,.1); box-shadow: none; }
.tab-btn.active { color: white; border-bottom-color: white; }
.app-header-right { margin-left: auto; display: flex; align-items: center; gap: .75rem; }
.user-identity { font-size: .8125rem; opacity: .9; text-transform: none; letter-spacing: normal; font-weight: 400; }
.btn-logout {
  padding: .35rem .85rem; background: rgba(255,255,255,.15);
  border: 1px solid rgba(255,255,255,.4); color: white;
  border-radius: var(--md-radius-sm); font-size: .75rem;
  box-shadow: none;
}
.btn-logout:hover { background: rgba(255,255,255,.25); box-shadow: none; }
.app-main { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
.loading-state, .error-state, .not-admin {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  height: 100%; gap: 1rem; color: var(--md-text-secondary);
}
.spinner {
  width: 36px; height: 36px; border: 3px solid #ddd;
  border-top-color: var(--md-primary); border-radius: 50%; animation: spin .7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>

