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
      <LoginPage v-if="!session.loggedIn" @logged-in="onLoggedIn" />

      <!-- Not admin notice -->
      <div v-else-if="!session.isAdmin" class="not-admin">
        <p>You do not have administrator rights to access this page.</p>
        <button class="btn-neutral" @click="handleLogout">Sign out</button>
      </div>

      <!-- Loading state -->
      <div v-else-if="modelLoading" class="loading-state">
        <div class="spinner"></div>
        <span>Loading auth data…</span>
      </div>

      <!-- Error state -->
      <div v-else-if="modelError" class="error-state">
        <p>{{ modelError }}</p>
        <button class="btn-primary" @click="refresh">Retry</button>
      </div>

      <!-- Users tab -->
      <UserList
        v-else-if="activeTab === 'users'"
        :users="model?.users ?? []"
        :groups="model?.groups ?? []"
        :modules="modules"
        :loading="modelLoading"
        @refresh="refresh"
      />

      <!-- Groups tab -->
      <GroupList
        v-else-if="activeTab === 'groups'"
        :groups="model?.groups ?? []"
        :loading="modelLoading"
        @refresh="refresh"
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
import { ref, computed, onMounted } from 'vue';
import { session, initSession, doLogout } from './composables/useSession';
import { useAuthModel }                   from './composables/useAuthModel';
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

async function refresh() {
  await refreshModel();
}

// ── Session ────────────────────────────────────────────────────────────────
onMounted(async () => {
  await initSession();
  if (session.loggedIn && session.isAdmin) {
    await refresh();
  }
});

async function onLoggedIn() {
  await refresh();
}

async function handleLogout() {
  await doLogout();
}
</script>

<style>
/* Global resets */
*, *::before, *::after { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; }
</style>

<style scoped>
.app-shell { display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
.app-header {
  display: flex; align-items: center; gap: 1rem;
  background: #1a73e8; color: white; padding: 0 1rem; height: 48px;
  flex-shrink: 0;
}
.app-brand { font-size: 1.1rem; font-weight: 700; letter-spacing: .03em; }
.app-tabs { display: flex; gap: 0; height: 100%; }
.tab-btn {
  height: 100%; padding: 0 1.1rem; background: none; border: none;
  color: rgba(255,255,255,.75); font-size: .9rem; font-weight: 600;
  cursor: pointer; border-bottom: 3px solid transparent; transition: all .15s;
}
.tab-btn:hover  { color: white; background: rgba(255,255,255,.1); }
.tab-btn.active { color: white; border-bottom-color: white; }
.app-header-right { margin-left: auto; display: flex; align-items: center; gap: .75rem; }
.user-identity { font-size: .85rem; opacity: .85; }
.btn-logout {
  padding: .3rem .75rem; background: rgba(255,255,255,.15);
  border: 1px solid rgba(255,255,255,.4); color: white;
  border-radius: 4px; cursor: pointer; font-size: .82rem;
}
.btn-logout:hover { background: rgba(255,255,255,.25); }
.app-main { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
.loading-state, .error-state, .not-admin {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  height: 100%; gap: 1rem; color: #555;
}
.spinner {
  width: 36px; height: 36px; border: 3px solid #ddd;
  border-top-color: #1a73e8; border-radius: 50%; animation: spin .7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.btn-primary { padding: .45rem 1rem; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: .875rem; font-weight: 600; }
.btn-neutral { padding: .45rem 1rem; background: #e0e0e0; color: #333; border: none; border-radius: 4px; cursor: pointer; font-size: .875rem; font-weight: 600; }
</style>

