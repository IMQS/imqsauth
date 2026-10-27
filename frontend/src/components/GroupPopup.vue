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

// Ignore the 'group' prop entirely when in add mode, even if the caller
// mistakenly still passes a (stale) previously-selected group. This prevents
// a brand new group from silently inheriting another group's module/permissions.
const editingGroup = props.isAdd ? undefined : props.group;

const saving              = ref(false);
const saveError           = ref('');
const showDiscardConfirm  = ref(false);
const groupNameError      = ref(false);
const permissionsError    = ref(false);

const groupName       = ref(editingGroup?.name ?? '');
const originalModule  = editingGroup?.moduleName ?? editingGroup?.permissions[0]?.module ?? '';
const selectedModule  = ref(originalModule);
const checkedIds      = reactive(new Set<string>(editingGroup?.permissions.map(p => p.id) ?? []));


const moduleOptions = computed(() => allModuleOptions());
const allPermsByModule = computed(() => permissionsByModule());

const modulePermissions = computed((): Permission[] => {
  const isModAccess = selectedModule.value === 'Module Access';
  let perms = (allPermsByModule.value.get(selectedModule.value) ?? [])
    .filter(p => !['Administrator', 'Enabled'].includes(p.friendlyName));

  if (isModAccess) {
    // Include all ModuleAccess permissions across modules
    const extra: Permission[] = [];
    for (const arr of allPermsByModule.value.values()) {
      for (const p of arr) if (p.name.includes('ModuleAccess') && !extra.find(e => e.id === p.id)) extra.push(p);
    }
    perms = extra;
  }

  // Always include any already-checked permissions, even ones belonging to a
  // different module than the one currently selected. Without this, there is
  // no checkbox rendered for them once you switch modules, so there would be
  // no way to uncheck/remove them when moving a group to a different module.
  for (const arr of allPermsByModule.value.values()) {
    for (const p of arr) {
      if (checkedIds.has(p.id) && !perms.find(e => e.id === p.id)) perms.push(p);
    }
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
  if (props.isAdd) return groupName.value.length > 0 || checkedIds.size > 0 || selectedModule.value !== originalModule;
  const origName = editingGroup?.name ?? '';
  if (groupName.value !== origName) return true;
  if (selectedModule.value !== originalModule) return true;
  const origIds = new Set(editingGroup?.permissions.map(p => p.id) ?? []);
  if (origIds.size !== checkedIds.size) return true;
  for (const id of origIds) if (!checkedIds.has(id)) return true;
  return false;
});

// ── Actions ────────────────────────────────────────────────────────────────

function onModuleChange() {
  // Switching the selected module only changes which module's full permission
  // catalog is shown for *adding new* permissions. Already-checked permissions
  // (from any module) remain checked and still render a checkbox - see the
  // modulePermissions computed above - so they can be unchecked/removed here.
}

function togglePerm(perm: Permission) {
  checkedIds.has(perm.id) ? checkedIds.delete(perm.id) : checkedIds.add(perm.id);
}

function validate(): boolean {
  groupNameError.value = !groupName.value.trim();
  // Permissions are not mandatory - a group may legitimately have none assigned
  // (e.g. a freshly created placeholder group), and that must not block saving
  // other changes such as renaming the group.
  permissionsError.value = false;
  return !groupNameError.value;
}

function groupExists(): boolean {
  const orig = props.isAdd ? '' : (editingGroup?.name ?? '');
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
    } else if (editingGroup?.name && groupName.value !== editingGroup.name) {
      await api.updateGroup(editingGroup.name, groupName.value);
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

