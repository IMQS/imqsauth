<template>
  <div class="group-list">
    <!-- Toolbar -->
    <div class="toolbar">
      <button class="btn-primary" @click="openAdd" :disabled="!isAdmin">+ Add Group</button>
      <button class="btn-neutral" @click="openEdit" :disabled="!selectedGroup || !isAdmin">Edit</button>
      <button class="btn-danger"  @click="confirmDelete" :disabled="!selectedGroup || !isAdmin">Delete</button>
      <input class="search-box" v-model="search" placeholder="Search groups…" />
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
          <span class="group-module">{{ g.moduleName }}</span>
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

const filteredGroups = computed(() => {
  const q = search.value.toLowerCase();
  return props.groups.filter(g => !q || (g.name ?? '').toLowerCase().includes(q));
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

function selectGroup(g: Group) { selectedGroup.value = g; }

function openAdd() {
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

function onSaved(updatedGroups: Group[]) {
  showPopup.value = false;
  showToast('Group saved', '', 'success');
  emit('refresh');
}
</script>

<style scoped>
.group-list { display: flex; flex-direction: column; height: 100%; overflow: hidden; }
.toolbar {
  display: flex; align-items: center; gap: .5rem; flex-wrap: wrap;
  padding: .5rem .75rem; border-bottom: 1px solid #e0e0e0; background: #fafafa;
}
.search-box { padding: .35rem .6rem; border: 1px solid #ccc; border-radius: 4px; font-size: .85rem; min-width: 180px; margin-left: auto; }
.content-area { display: flex; flex: 1; overflow: hidden; }
.list-col { flex: 0 0 280px; border-right: 1px solid #e0e0e0; overflow-y: auto; }
.detail-col { flex: 1; padding: 1rem; overflow-y: auto; }
.group-item {
  padding: .5rem .75rem; border-bottom: 1px solid #f0f0f0; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center;
}
.group-item:hover { background: #f5f5f5; }
.group-item.selected { background: #e3f2fd; }
.group-name { font-size: .875rem; font-weight: 600; }
.group-module { font-size: .75rem; color: #888; }
.empty { text-align: center; color: #999; padding: 2rem; font-size: .85rem; }
.detail-title { margin: 0 0 .75rem; font-size: .9rem; font-weight: 700; }
.perm-module { margin-bottom: .6rem; }
.perm-module strong { font-size: .8rem; color: #444; }
.perm-module ul { margin: .2rem 0 0 1rem; padding: 0; }
.perm-module li { font-size: .8rem; color: #555; list-style: disc; }
button { padding: .4rem .85rem; border: none; border-radius: 4px; cursor: pointer; font-size: .85rem; font-weight: 600; }
.btn-primary { background: #1a73e8; color: white; }
.btn-primary:disabled { opacity: .5; cursor: not-allowed; }
.btn-neutral { background: #e0e0e0; color: #333; }
.btn-neutral:disabled { opacity: .5; cursor: not-allowed; }
.btn-danger  { background: #d32f2f; color: white; }
.btn-danger:disabled  { opacity: .5; cursor: not-allowed; }
</style>

