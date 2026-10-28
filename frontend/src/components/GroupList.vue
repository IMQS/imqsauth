<template>
  <div class="group-list">
    <!-- Toolbar -->
    <div class="toolbar">
      <button class="btn-primary" @click="openAdd" :disabled="!isAdmin">+ Add Group</button>
      <button class="btn-neutral" @click="openEdit" :disabled="!selectedGroup || !isAdmin">Edit</button>
      <button class="btn-danger"  @click="confirmDelete" :disabled="!selectedGroup || !isAdmin">Delete</button>
      <input class="search-box" v-model="search" placeholder="Search groups…" />
      <label class="chk-system-groups">
        <input type="checkbox" v-model="showSystemGroups" />
        Show admin/enabled
      </label>
    </div>

    <div class="content-area">
      <!-- Group list -->
      <div class="list-col">
        <div
          v-for="g in filteredGroups"
          :key="g.name"
          class="group-item"
          :class="{ selected: selectedGroup?.name === g.name }"
          @click="selectGroup(g)"
          @dblclick="openEdit"
        >
          <span class="group-name">{{ g.name }}</span>
          <span class="group-module">
            {{ g.moduleName }}<span v-if="hasMultipleModules(g)" class="multi-module-marker" title="This group has permissions spanning more than one module">*</span>
          </span>
        </div>
        <div v-if="filteredGroups.length === 0" class="empty">
          {{ loading ? 'Loading…' : 'No groups found.' }}
        </div>
      </div>

      <!-- Permissions detail -->
      <div class="detail-col">
        <template v-if="selectedGroup">
          <h4 class="detail-title">{{ selectedGroup.name }} — Permissions</h4>
          <div v-if="selectedGroup.permissions.length === 0" class="empty">No permissions assigned.</div>
          <div v-for="[mod, perms] in permsByModule" :key="mod" class="perm-module">
            <strong>{{ mod }}</strong>
            <ul>
              <li v-for="p in perms" :key="p.id">{{ p.friendlyName }}</li>
            </ul>
          </div>
        </template>
        <div v-else class="empty">Select a group to view its permissions.</div>
      </div>
    </div>

    <!-- Group popup -->
    <GroupPopup
      v-if="showPopup"
      :group="selectedGroup ?? undefined"
      :all-groups="groups"
      :is-add="isAddMode"
      @saved="onSaved"
      @close="showPopup = false"
    />

    <!-- Delete confirmation -->
    <ConfirmDialog
      :visible="showDeleteConfirm"
      title="Delete Group"
      :message="`Delete group '${selectedGroup?.name}'? This cannot be undone.`"
      confirm-label="Delete"
      variant="danger"
      @confirm="doDelete"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import type { Group } from '../services/auth';
import type { Permission } from '../services/permissions';
import { isLocalAdmin } from '../services/auth';
import * as api from '../services/api';
import { showToast } from '../composables/useToast';
import GroupPopup from './GroupPopup.vue';
import ConfirmDialog from './ConfirmDialog.vue';

const props = defineProps<{
  groups: Group[];
  loading: boolean;
}>();

const emit = defineEmits<{ (e: 'refresh'): void }>();

const isAdmin           = computed(() => isLocalAdmin());
const selectedGroup     = ref<Group | null>(null);
const showPopup         = ref(false);
const isAddMode         = ref(false);
const showDeleteConfirm = ref(false);
const search            = ref('');
const showSystemGroups  = ref(false);

// 'admin' and 'enabled' aren't really groups - they just reflect the single
// Administrator / Enabled permissions respectively, and are managed directly
// via the checkboxes on the user edit popup. Hide them from this list by
// default since they tend to confuse the group list with non-module entries.
const SYSTEM_GROUP_NAMES = new Set(['admin', 'enabled']);

const filteredGroups = computed(() => {
  const q = search.value.toLowerCase();
  return props.groups
    .filter(g => showSystemGroups.value || !SYSTEM_GROUP_NAMES.has(g.name ?? ''))
    .filter(g => !q || (g.name ?? '').toLowerCase().includes(q));
});

const permsByModule = computed((): Map<string, Permission[]> => {
  const m = new Map<string, Permission[]>();
  if (!selectedGroup.value) return m;
  for (const p of selectedGroup.value.permissions) {
    const arr = m.get(p.module) ?? [];
    arr.push(p);
    m.set(p.module, arr);
  }
  return m;
});

/** True if the group's permissions span more than one module. */
function hasMultipleModules(g: Group): boolean {
  const mods = new Set(g.permissions.map(p => p.module).filter(Boolean));
  return mods.size > 1;
}

function selectGroup(g: Group) { selectedGroup.value = g; }

function openAdd() {
  // Clear any pre-existing selection so the popup doesn't inherit a stale
  // group's module/permissions when adding a brand new group.
  selectedGroup.value = null;
  isAddMode.value = true;
  showPopup.value = true;
}

function openEdit() {
  if (!selectedGroup.value) return;
  isAddMode.value = false;
  showPopup.value = true;
}

function confirmDelete() {
  if (!selectedGroup.value) return;
  showDeleteConfirm.value = true;
}

async function doDelete() {
  showDeleteConfirm.value = false;
  if (!selectedGroup.value?.name) return;
  try {
    await api.deleteGroup(selectedGroup.value.name);
    showToast('Group deleted', selectedGroup.value.name, 'success');
    selectedGroup.value = null;
    emit('refresh');
  } catch (e: unknown) {
    showToast('Delete failed', e instanceof Error ? e.message : '', 'error');
  }
}

function onSaved(updatedGroups: Group[], savedGroupName: string) {
  showPopup.value = false;
  showToast('Group saved', '', 'success');
  // Keep the (possibly renamed) group selected and showing its freshly
  // saved permissions, instead of losing the selection/detail panel while
  // the parent's full refresh is still in flight.
  selectedGroup.value = updatedGroups.find(g => g.name === savedGroupName) ?? null;
  emit('refresh');
}
</script>

<style scoped>
.group-list { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
.toolbar {
  display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
  padding: .5rem .75rem; border-bottom: 1px solid var(--md-outline-variant); background: var(--md-surface-variant);
}
.search-box { padding: .35rem .6rem; font-size: .85rem; min-width: 180px; margin-left: .25rem; }
.chk-system-groups { display: flex; align-items: center; gap: .35rem; font-size: .8125rem; color: var(--md-text-secondary); cursor: pointer; margin-left: auto; }
.content-area { display: flex; flex: 1; overflow: hidden; }
.list-col { flex: 0 0 280px; border-right: 1px solid var(--md-outline-variant); overflow-y: auto; }
.detail-col { flex: 1; padding: 1rem; overflow-y: auto; }
.group-item {
  padding: .5rem .75rem; border-bottom: 1px solid #f0f0f0; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center;
}
.group-item:hover { background: #f5f5f5; }
.group-item.selected { background: #bbdefb; }
.group-name { font-size: .875rem; font-weight: 500; }
.group-module { font-size: .75rem; color: var(--md-text-secondary); }
.multi-module-marker { color: var(--md-danger); font-weight: 700; margin-left: .15rem; cursor: help; }
.empty { text-align: center; color: #999; padding: 2rem; font-size: .85rem; }
.detail-title { margin: 0 0 .75rem; font-size: .9rem; font-weight: 500; }
.perm-module { margin-bottom: .6rem; }
.perm-module strong { font-size: .8rem; color: var(--md-text-primary); }
.perm-module ul { margin: .2rem 0 0 1rem; padding: 0; }
.perm-module li { font-size: .8rem; color: var(--md-text-secondary); list-style: disc; }
</style>

