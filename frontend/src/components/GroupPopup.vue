<template>
  <div class="popup-overlay" role="dialog" aria-modal="true">
    <div class="popup-container">
      <div class="popup-header">{{ isAdd ? 'Add New Group' : 'Edit Group' }}</div>

      <div class="popup-body">
        <!-- Left: config -->
        <div class="config-col">
          <div class="form-row">
            <label :class="['field-label', groupNameError && 'field-label--error']">
              Group Name *
            </label>
            <input v-model="groupName" class="field-input" :class="{ 'input-error': groupNameError }" />
          </div>

          <div class="form-row">
            <label class="field-label">Module</label>
            <select v-model="selectedModule" @change="onModuleChange" class="field-input">
              <option value="">— Choose a module —</option>
              <option v-for="m in moduleOptions" :key="m.id" :value="m.value">{{ m.value }}</option>
            </select>
          </div>

          <div class="perm-section">
            <label :class="['field-label', permissionsError && 'field-label--error']">
              Permissions
            </label>
            <div class="perm-list">
              <label v-for="perm in modulePermissions" :key="perm.id" class="perm-item">
                <input
                  type="checkbox"
                  :checked="checkedIds.has(perm.id)"
                  @change="togglePerm(perm)"
                />
                {{ perm.friendlyName }}
              </label>
              <span v-if="modulePermissions.length === 0 && selectedModule" class="no-perms">
                No permissions for this module.
              </span>
              <span v-if="!selectedModule" class="no-perms">Select a module to see permissions.</span>
            </div>
          </div>
        </div>

        <!-- Right: active permissions summary -->
        <div class="summary-col">
          <h4 class="summary-title">Active Permissions</h4>
          <div v-if="activeByModule.size === 0" class="no-perms">None selected.</div>
          <div v-for="[mod, perms] in activeByModule" :key="mod" class="summary-module">
            <strong>{{ mod }}</strong>
            <ul>
              <li v-for="p in perms" :key="p.id">{{ p.friendlyName }}</li>
            </ul>
          </div>
        </div>
      </div>

      <p v-if="saveError" class="save-error">{{ saveError }}</p>

      <div class="popup-footer">
        <button class="btn-neutral" @click="cancel">Cancel</button>
        <button class="btn-primary" :disabled="!isDirty || saving" @click="save">
          {{ saving ? 'Saving…' : 'Save' }}
        </button>
      </div>
    </div>
  </div>

  <!-- Discard confirmation -->
  <ConfirmDialog
    :visible="showDiscardConfirm"
    title="Discard changes?"
    message="All unsaved edits will be lost."
    confirm-label="Discard"
    variant="danger"
    @confirm="forceClose"
    @cancel="showDiscardConfirm = false"
  />
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { Group } from '../services/auth';
import { Permission, permissionsByModule } from '../services/permissions';
import { allModuleOptions } from '../services/modules';
import * as api from '../services/api';
import ConfirmDialog from './ConfirmDialog.vue';

const props = defineProps<{
  group?: Group;         // undefined = add mode
  allGroups: Group[];
  isAdd: boolean;
}>();

const emit = defineEmits<{
  (e: 'saved', groups: Group[]): void;
  (e: 'close'): void;
}>();

// ── State ──────────────────────────────────────────────────────────────────

const saving              = ref(false);
const saveError           = ref('');
const showDiscardConfirm  = ref(false);
const groupNameError      = ref(false);
const permissionsError    = ref(false);

const groupName      = ref(props.group?.name ?? '');
const selectedModule = ref(props.group?.moduleName ?? props.group?.permissions[0]?.module ?? '');
const checkedIds     = reactive(new Set<string>(props.group?.permissions.map(p => p.id) ?? []));

const moduleOptions = computed(() => allModuleOptions());
const allPermsByModule = computed(() => permissionsByModule());

const modulePermissions = computed((): Permission[] => {
  const isModAccess = selectedModule.value === 'Module Access';
  const perms = (allPermsByModule.value.get(selectedModule.value) ?? [])
    .filter(p => !['Administrator', 'Enabled'].includes(p.friendlyName));
  if (isModAccess) {
    // Include all ModuleAccess permissions across modules
    const extra: Permission[] = [];
    for (const arr of allPermsByModule.value.values()) {
      for (const p of arr) if (p.name.includes('ModuleAccess') && !extra.find(e => e.id === p.id)) extra.push(p);
    }
    return extra.sort((a, b) => a.friendlyName.localeCompare(b.friendlyName));
  }
  return perms.sort((a, b) => a.friendlyName.localeCompare(b.friendlyName));
});

const activeByModule = computed((): Map<string, Permission[]> => {
  const m = new Map<string, Permission[]>();
  for (const id of checkedIds) {
    for (const arr of allPermsByModule.value.values()) {
      const found = arr.find(p => p.id === id);
      if (found) {
        const existing = m.get(found.module) ?? [];
        existing.push(found);
        m.set(found.module, existing);
      }
    }
  }
  return m;
});

const isDirty = computed(() => {
  if (props.isAdd) return groupName.value.length > 0 || checkedIds.size > 0;
  const origName = props.group?.name ?? '';
  if (groupName.value !== origName) return true;
  const origIds = new Set(props.group?.permissions.map(p => p.id) ?? []);
  if (origIds.size !== checkedIds.size) return true;
  for (const id of origIds) if (!checkedIds.has(id)) return true;
  return false;
});

// ── Actions ────────────────────────────────────────────────────────────────

function onModuleChange() {
  // Keep already-checked permissions from other modules; just show new module's perms
}

function togglePerm(perm: Permission) {
  checkedIds.has(perm.id) ? checkedIds.delete(perm.id) : checkedIds.add(perm.id);
}

function validate(): boolean {
  groupNameError.value   = !groupName.value.trim();
  permissionsError.value = checkedIds.size === 0;
  return !groupNameError.value && !permissionsError.value;
}

function groupExists(): boolean {
  const orig = props.isAdd ? '' : (props.group?.name ?? '');
  if (groupName.value === orig) return false;
  return props.allGroups.some(g => g.name === groupName.value);
}

async function save() {
  saveError.value = '';
  if (!validate()) { saveError.value = 'Please fill in all required fields.'; return; }
  if (groupExists()) { saveError.value = 'A group with that name already exists.'; return; }

  saving.value = true;
  try {
    if (props.isAdd) {
      await api.createGroup(groupName.value);
    } else if (props.group?.name && groupName.value !== props.group.name) {
      await api.updateGroup(props.group.name, groupName.value);
    }
    await api.setGroupRoles(groupName.value, [...checkedIds]);

    // Reload groups and emit
    const rawGroups = await api.getGroups();
    const groups = rawGroups.map(rg => { const g = new Group(); g.fromRaw(rg); return g; });
    emit('saved', groups);
  } catch (e: unknown) {
    saveError.value = e instanceof Error ? e.message : 'Save failed';
  } finally {
    saving.value = false;
  }
}

function cancel() {
  if (isDirty.value) { showDiscardConfirm.value = true; return; }
  forceClose();
}

function forceClose() {
  showDiscardConfirm.value = false;
  emit('close');
}
</script>

<style scoped>
.popup-overlay {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,.4);
  display: flex; align-items: center; justify-content: center; padding: 1rem;
}
.popup-container {
  background: white; border-radius: 6px; width: 860px; max-width: 100%;
  box-shadow: 0 4px 24px rgba(0,0,0,.2); display: flex; flex-direction: column;
  max-height: 90vh;
}
.popup-header {
  background: #f5f5f5; font-weight: 700; padding: .75rem 1rem;
  border-bottom: 1px solid #e0e0e0; border-radius: 6px 6px 0 0;
}
.popup-body { display: flex; gap: 0; flex: 1; overflow: hidden; }
.config-col { flex: 0 0 55%; padding: 1rem; overflow-y: auto; border-right: 1px solid #e0e0e0; display: flex; flex-direction: column; gap: .8rem; }
.summary-col { flex: 1; padding: 1rem; overflow-y: auto; }
.form-row { display: flex; flex-direction: column; gap: .25rem; }
.field-label { font-size: .8rem; font-weight: 600; color: #555; }
.field-label--error { color: #c0392b; }
.field-input {
  width: 100%; box-sizing: border-box;
  padding: .4rem .6rem; border: 1px solid #ccc; border-radius: 3px; font-size: .875rem;
}
.input-error { border-color: #c0392b; }
.perm-section { display: flex; flex-direction: column; gap: .3rem; flex: 1; }
.perm-list { display: flex; flex-direction: column; gap: .3rem; overflow-y: auto; max-height: 300px; padding: .25rem; }
.perm-item { display: flex; align-items: center; gap: .4rem; font-size: .83rem; cursor: pointer; }
.no-perms { font-size: .8rem; color: #999; font-style: italic; }
.summary-title { font-size: .8rem; font-weight: 700; text-transform: uppercase; color: #666; margin: 0 0 .5rem; }
.summary-module { margin-bottom: .5rem; }
.summary-module strong { font-size: .8rem; color: #444; }
.summary-module ul { margin: .2rem 0 0 1rem; padding: 0; }
.summary-module li { font-size: .8rem; color: #555; list-style: disc; }
.save-error { color: #c0392b; font-size: .82rem; margin: 0; padding: .25rem 1rem; }
.popup-footer {
  display: flex; justify-content: flex-end; gap: .6rem;
  padding: .75rem 1rem; border-top: 1px solid #e0e0e0;
}
button { padding: .45rem 1rem; border: none; border-radius: 4px; cursor: pointer; font-size: .875rem; font-weight: 600; }
.btn-primary { background: #1a73e8; color: white; }
.btn-primary:disabled { opacity: .6; cursor: not-allowed; }
.btn-neutral { background: #e0e0e0; color: #333; }
</style>

