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
            <div class="perm-header-row">
              <label :class="['field-label', permissionsError && 'field-label--error']">
                Permissions
              </label>
              <button
                type="button"
                class="btn-toggle-all"
                :disabled="!selectedModule || currentModulePerms.length === 0"
                @click="toggleAllPerms"
              >
                {{ allCurrentModuleChecked ? 'Remove All' : 'Add All' }}
              </button>
            </div>
            <div class="perm-list">
              <transition-group name="perm-item" tag="div" class="perm-list-items">
                <label v-for="perm in modulePermissions" :key="perm.id" class="perm-item">
                  <span class="perm-item-left">
                    <input
                      type="checkbox"
                      :checked="checkedIds.has(perm.id)"
                      @change="togglePerm(perm)"
                    />
                    {{ perm.friendlyName }}
                  </span>
                  <span v-if="perm.module !== selectedModule" class="perm-other-module">({{ perm.module }})</span>
                </label>
              </transition-group>
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
  (e: 'saved', groups: Group[], savedGroupName: string): void;
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

/** Permissions belonging to the currently selected module's own catalog
 *  (i.e. excluding any already-checked permissions that happen to belong
 *  to a different module). This is what "Add All" / "Remove All" operates on. */
const currentModulePerms = computed((): Permission[] => {
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

  return perms;
});

const modulePermissions = computed((): Permission[] => {
  const perms = [...currentModulePerms.value];

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

/** True once every permission belonging to the currently selected module is checked. */
const allCurrentModuleChecked = computed(() =>
  currentModulePerms.value.length > 0 && currentModulePerms.value.every(p => checkedIds.has(p.id))
);

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

/**
 * Acts as "Add All" when not every permission of the selected module is
 * checked yet - adds only the currently selected module's own permissions.
 * Acts as "Remove All" once they're all checked - unchecks every permission
 * currently visible in the list (including any cross-module ones), so the
 * whole list empties out and the same checkbox-removal animation plays.
 */
function toggleAllPerms() {
  if (allCurrentModuleChecked.value) {
    for (const p of modulePermissions.value) checkedIds.delete(p.id);
  } else {
    for (const p of currentModulePerms.value) checkedIds.add(p.id);
  }
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
    emit('saved', groups, groupName.value);
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
  background: var(--md-surface); border-radius: var(--md-radius-md); width: 860px; max-width: 100%;
  box-shadow: var(--md-elevation-5); display: flex; flex-direction: column;
  height: 640px; max-height: 90vh;
}
.popup-header {
  background: var(--md-surface-variant); font-weight: 500; font-size: 1.0625rem; padding: .75rem 1rem;
  border-bottom: 1px solid var(--md-outline-variant); border-radius: var(--md-radius-md) var(--md-radius-md) 0 0;
}
.popup-body { display: flex; gap: 0; flex: 1; overflow: hidden; }
.config-col { flex: 0 0 55%; padding: 1rem; overflow-y: auto; border-right: 1px solid var(--md-outline-variant); display: flex; flex-direction: column; gap: .8rem; }
.summary-col { flex: 1; padding: 1rem; overflow-y: auto; }
.form-row { display: flex; flex-direction: column; gap: .25rem; }
.field-label { font-size: .8rem; font-weight: 500; color: var(--md-text-secondary); }
.field-label--error { color: var(--md-danger); }
.field-input {
  width: 100%; box-sizing: border-box;
  padding: .4rem .6rem; font-size: .875rem;
}
.input-error { border-color: var(--md-danger); }
.perm-section { display: flex; flex-direction: column; gap: .3rem; flex: 1; min-height: 0; }
.perm-header-row { display: flex; align-items: center; justify-content: space-between; gap: .5rem; }
.btn-toggle-all {
  padding: .25rem .65rem; border: 1px solid var(--md-primary); border-radius: var(--md-radius-sm);
  background: var(--md-surface); color: var(--md-primary); font-size: .72rem; font-weight: 500;
  letter-spacing: .02em; text-transform: uppercase; cursor: pointer; box-shadow: none;
}
.btn-toggle-all:hover:not(:disabled) { background: var(--md-primary-light); box-shadow: none; }
.btn-toggle-all:disabled { opacity: .5; cursor: not-allowed; border-color: #ccc; color: #999; box-shadow: none; }
.perm-list { display: flex; flex-direction: column; gap: .3rem; overflow-y: auto; overflow-x: hidden; flex: 1; min-height: 0; padding: .25rem; }
.perm-list-items { position: relative; display: flex; flex-direction: column; gap: .3rem; }
.perm-item { display: flex; align-items: center; justify-content: space-between; gap: .4rem; font-size: .83rem; cursor: pointer; }
.perm-item-left { display: flex; align-items: center; gap: .4rem; }
.perm-other-module { color: #bbb; font-size: .78rem; margin-left: auto; white-space: nowrap; }
.perm-item-move { transition: transform .25s ease; }
.perm-item-enter-active, .perm-item-leave-active { transition: opacity .25s ease, transform .25s ease; }
.perm-item-enter-from, .perm-item-leave-to { opacity: 0; transform: translateX(10px); }
.perm-item-leave-active { position: absolute; width: 100%; }
.no-perms { font-size: .8rem; color: #999; font-style: italic; }
.summary-title { font-size: .75rem; font-weight: 500; letter-spacing: .03em; text-transform: uppercase; color: var(--md-text-secondary); margin: 0 0 .5rem; }
.summary-module { margin-bottom: .5rem; }
.summary-module strong { font-size: .8rem; color: var(--md-text-primary); }
.summary-module ul { margin: .2rem 0 0 1rem; padding: 0; }
.summary-module li { font-size: .8rem; color: var(--md-text-secondary); list-style: disc; }
.save-error { color: var(--md-danger); font-size: .82rem; margin: 0; padding: .25rem 1rem; }
.popup-footer {
  display: flex; justify-content: flex-end; gap: .6rem;
  padding: .75rem 1rem; border-top: 1px solid var(--md-outline-variant);
}
</style>

