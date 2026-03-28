<template>
  <div class="popup-overlay" role="dialog" aria-modal="true" :aria-labelledby="'upopup-title-' + uid">
    <div class="popup-container">
      <!-- Header -->
      <div class="popup-header" :id="'upopup-title-' + uid">
        {{ isAdd ? 'Add New User' : 'Edit User' }}
      </div>

      <!-- Locked banner -->
      <div v-if="user.accountLocked" class="locked-banner">
        <span>⚠ This account is locked due to too many failed login attempts.</span>
        <button class="btn-warning" @click="unlock">Unlock Account</button>
      </div>

      <div class="popup-body">
        <!-- Left column: account info -->
        <section class="popup-section">
          <h3 class="section-label">Account Information</h3>
          <div class="form-grid">
            <label>Name <span v-if="isIMQS" class="required">*</span></label>
            <input v-model="form.name" :disabled="!isIMQS || user.archived" />

            <label>Surname <span v-if="isIMQS" class="required">*</span></label>
            <input v-model="form.surname" :disabled="!isIMQS || user.archived" />

            <label>Username</label>
            <input v-model="form.username" :disabled="!isIMQS || user.archived" />

            <label>Email <span v-if="isIMQS" class="required">*</span></label>
            <input v-model="form.email" type="email" :disabled="!isIMQS || user.archived" />

            <label>Mobile</label>
            <input v-model="form.mobile" :disabled="!isIMQS || user.archived" />

            <label>Telephone</label>
            <input v-model="form.telephone" :disabled="!isIMQS || user.archived" />

            <label>Remarks</label>
            <textarea v-model="form.remarks" :disabled="!isIMQS || user.archived" rows="2" />

            <template v-if="isAdd">
              <label>Password <span class="required">*</span></label>
              <input v-model="form.password" type="password" />
            </template>
          </div>

          <div class="checkbox-row">
            <label class="chk-label">
              <input type="checkbox" v-model="enabledChecked" :disabled="!canEditAdmin" />
              Enabled User
            </label>
            <label class="chk-label">
              <input type="checkbox" v-model="adminChecked" :disabled="!canEditAdmin" />
              Administrator
            </label>
          </div>

          <div class="meta-info">
            <span v-if="user.created">Created: {{ fmtDate(user.created) }} by {{ user.createdBy }}</span>
            <span v-if="user.modified">Modified: {{ fmtDate(user.modified) }} by {{ user.modifiedBy }}</span>
          </div>
        </section>

        <!-- Right column: groups by module -->
        <section class="popup-section groups-section">
          <div class="groups-col">
            <h3 class="section-label">Groups by Module</h3>
            <div v-for="mod in modules" :key="mod.id" class="module-block">
              <button class="module-toggle" @click="toggleModule(mod.id)">
                <span class="toggle-icon">{{ expandedModules.has(mod.id) ? '−' : '+' }}</span>
                {{ mod.value }}
              </button>
              <transition name="expand">
                <div v-if="expandedModules.has(mod.id)" class="module-groups">
                  <template v-if="moduleGroups(mod).length === 0">
                    <span class="no-groups">No associated groups</span>
                  </template>
                  <label v-for="g in moduleGroups(mod)" :key="g.name" class="chk-label group-chk">
                    <input
                      type="checkbox"
                      :checked="selectedGroupNames.has(g.name!)"
                      @change="toggleGroup(g.name!)"
                      :disabled="user.archived"
                    />
                    {{ g.name }}
                  </label>
                </div>
              </transition>
            </div>
          </div>

          <div class="permissions-col">
            <h3 class="section-label">Active Permissions</h3>
            <div v-for="[mod, perms] in activePermsByModule" :key="mod" class="active-perm-block">
              <strong class="active-perm-module">{{ mod }}</strong>
              <ul>
                <li v-for="p in perms" :key="p.id">{{ p.friendlyName }}</li>
              </ul>
            </div>
            <span v-if="activePermsByModule.size === 0" class="no-groups">None</span>
          </div>
        </section>
      </div>

      <!-- Footer -->
      <div class="popup-footer">
        <button class="btn-neutral" @click="$emit('close')">Cancel</button>
        <button class="btn-primary" :disabled="!isDirty || saving" @click="save">
          {{ saving ? 'Saving…' : 'Save' }}
        </button>
      </div>

      <p v-if="saveError" class="save-error">{{ saveError }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue';
import { User, Group } from '../services/auth';
import { Permissions, Permission } from '../services/permissions';
import { AuthModule } from '../services/modules';
import type { ModuleOption } from '../services/modules';
import type { UserPostData } from '../services/types';
import * as api from '../services/api';
import { getStoredUserId } from '../services/auth';

const props = defineProps<{
  user: User;
  groups: Group[];
  modules: ModuleOption[];
  isAdd: boolean;
}>();

const emit = defineEmits<{
  (e: 'saved'): void;
  (e: 'close'): void;
}>();

const uid        = Math.random().toString(36).slice(2);
const saving     = ref(false);
const saveError  = ref('');

const form = reactive({
  name:      props.user.name      ?? '',
  surname:   props.user.surname   ?? '',
  username:  props.user.username  ?? '',
  email:     props.user.email     ?? '',
  mobile:    props.user.mobileNumber   ?? '',
  telephone: props.user.telephoneNumber ?? '',
  remarks:   props.user.remarks   ?? '',
  password:  '',
});

const isIMQS = computed(() => props.user.isIMQSUser());
const isSelf = computed(() => getStoredUserId() === props.user.userId);
const canEditAdmin = computed(() => !isSelf.value && !props.user.archived);

// Track selected groups by name
const selectedGroupNames = reactive(new Set<string>(props.user.groups.map(g => g.name!)));
const expandedModules    = reactive(new Set<string>());

// Enabled / Admin track the "enabled" and "admin" groups
const enabledChecked = computed({
  get: () => selectedGroupNames.has('enabled'),
  set: (v) => v ? selectedGroupNames.add('enabled') : selectedGroupNames.delete('enabled'),
});
const adminChecked = computed({
  get: () => selectedGroupNames.has('admin'),
  set: (v) => v ? selectedGroupNames.add('admin') : selectedGroupNames.delete('admin'),
});

function toggleModule(id: string) {
  expandedModules.has(id) ? expandedModules.delete(id) : expandedModules.add(id);
}

function toggleGroup(name: string) {
  selectedGroupNames.has(name) ? selectedGroupNames.delete(name) : selectedGroupNames.add(name);
}

const isModuleAccess = (n: string) => n.includes('ModuleAccess');

function moduleGroups(mod: ModuleOption): Group[] {
  const seen = new Set<string>();
  const result: Group[] = [];
  for (const g of props.groups) {
    if (!g.name || g.name === 'admin' || g.name === 'enabled') continue;
    for (const perm of g.permissions) {
      const belongs =
        perm.module === mod.value ||
        (mod.id === 'MODULE_ACCESS' && isModuleAccess(perm.name));
      if (belongs && !seen.has(g.name)) {
        seen.add(g.name);
        result.push(g);
      }
    }
  }
  return result;
}

const activePermsByModule = computed((): Map<string, Permission[]> => {
  const m = new Map<string, Permission[]>();
  for (const g of props.groups) {
    if (!selectedGroupNames.has(g.name!)) continue;
    for (const perm of g.permissions) {
      const arr = m.get(perm.module) ?? [];
      arr.push(perm);
      m.set(perm.module, arr);
    }
  }
  return m;
});

const isDirty = computed(() => {
  if (form.name !== (props.user.name ?? ''))      return true;
  if (form.surname !== (props.user.surname ?? ''))return true;
  if (form.email !== (props.user.email ?? ''))    return true;
  if (form.username !== (props.user.username ?? '')) return true;
  if (form.mobile !== (props.user.mobileNumber ?? '')) return true;
  if (form.telephone !== (props.user.telephoneNumber ?? '')) return true;
  if (form.remarks !== (props.user.remarks ?? '')) return true;
  if (isAdd.value && form.password) return true;
  // group membership change
  const original = new Set(props.user.groups.map(g => g.name!));
  if (original.size !== selectedGroupNames.size) return true;
  for (const n of original) if (!selectedGroupNames.has(n)) return true;
  return false;
});

const isAdd = computed(() => props.isAdd);

function fmtDate(d?: string) {
  if (!d) return '—';
  try {
    const dt = new Date(d);
    if (dt.getFullYear() <= 1) return '—';
    return dt.toLocaleDateString();
  } catch { return '—'; }
}

async function unlock() {
  if (!props.user.userId) return;
  try {
    await api.unlockUser(props.user.userId, props.user.username ?? props.user.email ?? '');
    emit('saved');
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : 'Unlock failed';
  }
}

async function save() {
  saveError.value = '';
  if (isIMQS.value) {
    if (!form.email && !form.username) { saveError.value = 'Email or username is required'; return; }
    if (!form.name)    { saveError.value = 'Name is required'; return; }
    if (!form.surname) { saveError.value = 'Surname is required'; return; }
    if (isAdd.value && !form.password) { saveError.value = 'Password is required for new users'; return; }
  }

  saving.value = true;
  try {
    const data: UserPostData = {
      userid:          props.user.userId,
      email:           form.email,
      username:        form.username,
      firstname:       form.name,
      lastname:        form.surname,
      mobilenumber:    form.mobile,
      telephonenumber: form.telephone,
      remarks:         form.remarks,
      authusertype:    props.user.isLDAPUser() ? 'LDAP' : 'DEFAULT',
      ...(form.password ? { password: form.password } : {}),
    };

    if (isAdd.value) {
      await api.createUser(data);
      // Now we need the created user's ID – re-fetch to get it
      // (The backend doesn't return the ID on create; we'll use set_user_groups after refresh)
    } else {
      await api.updateUser(data);
      if (props.user.userId) {
        await api.setUserGroups(props.user.userId, [...selectedGroupNames]);
      }
    }

    emit('saved');
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : 'Save failed';
  } finally {
    saving.value = false;
  }
}
</script>

<style scoped>
.popup-overlay {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,.4);
  display: flex; align-items: flex-start; justify-content: center;
  overflow-y: auto; padding: 1.5rem 1rem;
}
.popup-container {
  background: white; border-radius: 6px; width: 900px; max-width: 100%;
  box-shadow: 0 4px 24px rgba(0,0,0,.2); display: flex; flex-direction: column;
  max-height: calc(100vh - 3rem);
  flex-shrink: 0;
}
.popup-header {
  background: #f5f5f5; font-weight: 700; font-size: 1rem;
  padding: .75rem 1rem; border-bottom: 1px solid #e0e0e0; border-radius: 6px 6px 0 0;
  flex-shrink: 0;
}
.locked-banner {
  display: flex; align-items: center; justify-content: space-between;
  background: #fff3e0; border-left: 4px solid #f57c00;
  padding: .6rem 1rem; font-size: .875rem; color: #e65100;
  flex-shrink: 0;
}
.popup-body { display: flex; gap: 0; flex: 1; min-height: 0; overflow: hidden; }
.popup-section { padding: 1rem; flex: 1; overflow-y: auto; min-height: 0; }
.groups-section { display: flex; gap: .5rem; border-left: 1px solid #e0e0e0; }
.groups-col, .permissions-col { flex: 1; overflow-y: auto; min-height: 0; }
.section-label { font-size: .8rem; font-weight: 700; text-transform: uppercase; color: #666; margin: 0 0 .6rem; }
.form-grid { display: grid; grid-template-columns: 120px 1fr; gap: .45rem .75rem; align-items: start; }
.form-grid label { font-size: .8rem; font-weight: 600; color: #555; padding-top: .4rem; }
.form-grid input, .form-grid textarea {
  width: 100%; box-sizing: border-box; padding: .35rem .5rem;
  border: 1px solid #ccc; border-radius: 3px; font-size: .85rem;
}
.form-grid input:disabled, .form-grid textarea:disabled { background: #f9f9f9; color: #888; }
.required { color: #c0392b; }
.checkbox-row { display: flex; gap: 1.5rem; margin-top: .75rem; }
.chk-label { display: flex; align-items: center; gap: .4rem; font-size: .85rem; cursor: pointer; }
.meta-info { margin-top: .8rem; font-size: .75rem; color: #888; display: flex; flex-direction: column; gap: .2rem; }
.module-block { margin-bottom: .3rem; }
.module-toggle {
  width: 100%; text-align: left; padding: .35rem .5rem;
  background: #f0f0f0; border: none; border-radius: 3px; cursor: pointer;
  font-size: .83rem; font-weight: 600; display: flex; align-items: center; gap: .4rem;
}
.module-toggle:hover { background: #e4e4e4; }
.toggle-icon { font-size: 1rem; width: 1rem; }
.module-groups { padding: .3rem .5rem .3rem 1.5rem; display: flex; flex-direction: column; gap: .25rem; }
.group-chk { font-size: .82rem; }
.no-groups { font-size: .8rem; color: #999; font-style: italic; padding: .2rem .5rem; }
.active-perm-block { margin-bottom: .5rem; }
.active-perm-module { font-size: .8rem; font-weight: 700; color: #444; }
.active-perm-block ul { margin: .2rem 0 0 1rem; padding: 0; }
.active-perm-block li { font-size: .8rem; color: #555; list-style: disc; }
.popup-footer {
  display: flex; justify-content: flex-end; gap: .6rem;
  padding: .75rem 1rem; border-top: 1px solid #e0e0e0;
  flex-shrink: 0;
}
.save-error { color: #c0392b; font-size: .82rem; text-align: right; margin: -.25rem .75rem .5rem; }
button { padding: .45rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: .875rem; font-weight: 600; }
.btn-primary { background: #1a73e8; color: white; }
.btn-primary:disabled { opacity: .6; cursor: not-allowed; }
.btn-neutral { background: #e0e0e0; color: #333; }
.btn-warning { background: #f57c00; color: white; }
.expand-enter-active, .expand-leave-active { transition: all .18s ease; overflow: hidden; }
.expand-enter-from, .expand-leave-to { opacity: 0; max-height: 0; }
.expand-enter-to, .expand-leave-from { max-height: 400px; }
</style>

