<template>
  <div class="user-list">
    <!-- Toolbar -->
    <div class="toolbar">
      <button class="btn-primary" @click="openAdd" :disabled="!isAdmin">+ Add User</button>
      <button class="btn-neutral" @click="openEdit" :disabled="!selectedUser || !isAdmin">Edit</button>
      <button class="btn-danger"  @click="confirmArchive" :disabled="!selectedUser || !isAdmin">Archive</button>

      <div class="toolbar-filters">
        <label v-for="opt in filterOpts" :key="opt.value" class="filter-radio">
          <input type="radio" :value="opt.value" v-model="filter" @change="applyFilter" />
          {{ opt.label }}
        </label>
      </div>

      <input
        class="search-box"
        v-model="search"
        placeholder="Search users…"
        @input="applyFilter"
      />
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th @click="setSort('displayName')">Name {{ sortIcon('displayName') }}</th>
            <th @click="setSort('email')">Email {{ sortIcon('email') }}</th>
            <th @click="setSort('username')">Username {{ sortIcon('username') }}</th>
            <th @click="setSort('authType')">Type {{ sortIcon('authType') }}</th>
            <th>Groups</th>
            <th @click="setSort('lastLogin')">Last Login {{ sortIcon('lastLogin') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="u in displayedUsers"
            :key="u.userId"
            :class="{ selected: selectedUser?.userId === u.userId, archived: u.archived }"
            @click="selectUser(u)"
            @dblclick="openEdit"
          >
            <td>{{ u.displayName }}</td>
            <td>{{ u.email }}</td>
            <td>{{ u.username }}</td>
            <td><span class="badge" :class="'badge--' + authTypeClass(u)">{{ authTypeLabel(u) }}</span></td>
            <td class="groups-cell">{{ u.groups.map(g => g.name).join(', ') }}</td>
            <td>{{ fmtDate(u.lastLoginDate) }}</td>
          </tr>
          <tr v-if="displayedUsers.length === 0">
            <td colspan="6" class="empty">{{ loading ? 'Loading…' : 'No users found.' }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- User popup -->
    <UserPopup
      v-if="popupUser"
      :user="popupUser"
      :groups="groups"
      :modules="modules"
      :is-add="isAddMode"
      @saved="onSaved"
      @close="popupUser = null"
    />

    <!-- Archive confirmation -->
    <ConfirmDialog
      :visible="showArchiveConfirm"
      title="Archive User"
      :message="`Archive ${selectedUser?.displayName}? They will no longer be able to log in.`"
      confirm-label="Archive"
      variant="danger"
      @confirm="doArchive"
      @cancel="showArchiveConfirm = false"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { User, Group, authUserTypeFromNumber } from '../services/auth';
import { AuthUserType } from '../services/types';
import { authUserTypeLabel } from '../services/types';
import type { ModuleOption } from '../services/modules';
import * as api from '../services/api';
import { isLocalAdmin } from '../services/auth';
import UserPopup from './UserPopup.vue';
import ConfirmDialog from './ConfirmDialog.vue';
import { showToast } from '../composables/useToast';

const props = defineProps<{
  users: User[];
  groups: Group[];
  modules: ModuleOption[];
  loading: boolean;
}>();

const emit = defineEmits<{ (e: 'refresh'): void }>();

// ── State ──────────────────────────────────────────────────────────────────

const isAdmin = computed(() => isLocalAdmin());

const selectedUser      = ref<User | null>(null);
const popupUser         = ref<User | null>(null);
const isAddMode         = ref(false);
const showArchiveConfirm = ref(false);

// ── Filtering / sorting ────────────────────────────────────────────────────

type FilterMode = 'active' | 'archived' | 'all';
const filter  = ref<FilterMode>('active');
const search  = ref('');
const sortKey = ref<string>('displayName');
const sortAsc = ref(true);

const filterOpts = [
  { label: 'Active',   value: 'active'  as FilterMode },
  { label: 'Archived', value: 'archived'as FilterMode },
  { label: 'All',      value: 'all'     as FilterMode },
];

function applyFilter() { selectedUser.value = null; }

function setSort(key: string) {
  if (sortKey.value === key) sortAsc.value = !sortAsc.value;
  else { sortKey.value = key; sortAsc.value = true; }
}

function sortIcon(key: string) {
  if (sortKey.value !== key) return '';
  return sortAsc.value ? '▲' : '▼';
}

const displayedUsers = computed(() => {
  let list = props.users.slice();

  if (filter.value === 'active')   list = list.filter(u => !u.archived);
  if (filter.value === 'archived') list = list.filter(u => u.archived);

  if (search.value.trim()) {
    const q = search.value.toLowerCase();
    list = list.filter(u =>
      (u.displayName).toLowerCase().includes(q) ||
      (u.email ?? '').toLowerCase().includes(q) ||
      (u.username ?? '').toLowerCase().includes(q),
    );
  }

  const key = sortKey.value;
  list.sort((a, b) => {
    let av = '', bv = '';
    if (key === 'displayName') { av = a.displayName; bv = b.displayName; }
    else if (key === 'email')    { av = a.email ?? ''; bv = b.email ?? ''; }
    else if (key === 'username') { av = a.username ?? ''; bv = b.username ?? ''; }
    else if (key === 'authType') { av = authTypeLabel(a); bv = authTypeLabel(b); }
    else if (key === 'lastLogin') { av = a.lastLoginDate ?? ''; bv = b.lastLoginDate ?? ''; }
    const cmp = av.toLowerCase().localeCompare(bv.toLowerCase());
    return sortAsc.value ? cmp : -cmp;
  });

  return list;
});

// ── Actions ────────────────────────────────────────────────────────────────

function selectUser(u: User) { selectedUser.value = u; }

function openAdd() {
  const u = new User();
  u.authUserType = AuthUserType.IMQS;
  isAddMode.value = true;
  popupUser.value = u;
}

function openEdit() {
  if (!selectedUser.value) return;
  isAddMode.value = false;
  popupUser.value = selectedUser.value;
}

function confirmArchive() {
  if (!selectedUser.value) return;
  showArchiveConfirm.value = true;
}

async function doArchive() {
  showArchiveConfirm.value = false;
  if (!selectedUser.value?.userId) return;
  try {
    await api.archiveUser(selectedUser.value.userId);
    showToast('User archived', selectedUser.value.displayName, 'success');
    selectedUser.value = null;
    emit('refresh');
  } catch (e: unknown) {
    showToast('Archive failed', e instanceof Error ? e.message : '', 'error');
  }
}

function onSaved() {
  popupUser.value = null;
  showToast('Saved', '', 'success');
  emit('refresh');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function authTypeLabel(u: User) { return authUserTypeLabel(u.authUserType); }
function authTypeClass(u: User) {
  const map: Record<AuthUserType, string> = {
    [AuthUserType.IMQS]:  'imqs',
    [AuthUserType.LDAP]:  'ldap',
    [AuthUserType.OAuth]: 'oauth',
    [AuthUserType.MSAAD]: 'msaad',
  };
  return map[u.authUserType] ?? 'imqs';
}

function fmtDate(d?: string) {
  if (!d) return '—';
  try {
    const dt = new Date(d);
    if (dt.getFullYear() <= 1) return '—';
    return dt.toLocaleDateString();
  } catch { return '—'; }
}
</script>

<style scoped>
.user-list { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
.toolbar {
  display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
  padding: .5rem .75rem; border-bottom: 1px solid #e0e0e0; background: #fafafa;
}
.toolbar-filters { display: flex; gap: .75rem; margin-left: auto; }
.filter-radio { display: flex; align-items: center; gap: .3rem; font-size: .82rem; cursor: pointer; }
.search-box {
  padding: .35rem .6rem; border: 1px solid #ccc; border-radius: 4px;
  font-size: .85rem; min-width: 180px;
}
.table-wrap { flex: 1; overflow-y: auto; }
.data-table { width: 100%; border-collapse: collapse; font-size: .85rem; }
.data-table th {
  background: #f5f5f5; border-bottom: 2px solid #ddd; padding: .5rem .75rem;
  text-align: left; font-weight: 700; cursor: pointer; user-select: none; white-space: nowrap;
}
.data-table th:hover { background: #ebebeb; }
.data-table td { padding: .45rem .75rem; border-bottom: 1px solid #eee; }
.data-table tr.selected td { background: #e3f2fd; }
.data-table tr:hover td { background: #f5f5f5; }
.data-table tr.archived td { color: #999; font-style: italic; }
.empty { text-align: center; color: #999; padding: 2rem !important; }
.groups-cell { max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.badge {
  display: inline-block; padding: .15rem .45rem; border-radius: 10px;
  font-size: .72rem; font-weight: 700; text-transform: uppercase;
}
.badge--imqs  { background: #e3f2fd; color: #0d47a1; }
.badge--ldap  { background: #f3e5f5; color: #4a148c; }
.badge--oauth { background: #e8f5e9; color: #1b5e20; }
.badge--msaad { background: #fff3e0; color: #e65100; }
button { padding: .4rem .85rem; border: none; border-radius: 4px; cursor: pointer; font-size: .85rem; font-weight: 600; }
.btn-primary { background: #1a73e8; color: white; }
.btn-primary:disabled { opacity: .5; cursor: not-allowed; }
.btn-neutral { background: #e0e0e0; color: #333; }
.btn-neutral:disabled { opacity: .5; cursor: not-allowed; }
.btn-danger  { background: #d32f2f; color: white; }
.btn-danger:disabled  { opacity: .5; cursor: not-allowed; }
</style>

