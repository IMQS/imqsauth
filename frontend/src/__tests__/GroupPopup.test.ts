import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import GroupPopup from '../components/GroupPopup.vue';
import { Group } from '../services/auth';
import { Permissions } from '../services/permissions';

// Routes fetch calls based on URL so that a GET to '/groups' (used to reload
// the group list after save) returns an array, while every other call
// (update_group / create_group / set_group_roles) returns a simple "ok" text.
function mockFetchRouter() {
  return vi.fn().mockImplementation((url: string) => {
    if (url.includes('/groups')) {
      return Promise.resolve({
        ok: true, status: 200,
        json: () => Promise.resolve([]),
        text: () => Promise.resolve('[]'),
      });
    }
    return Promise.resolve({
      ok: true, status: 200,
      json: () => Promise.resolve('ok'),
      text: () => Promise.resolve('ok'),
    });
  });
}

describe('GroupPopup', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('allows renaming a group that has zero permissions assigned', async () => {
    const group = new Group('empty-group', []);
    globalThis.fetch = mockFetchRouter();

    const wrapper = mount(GroupPopup, {
      props: { group, allGroups: [group], isAdd: false },
      global: { stubs: { ConfirmDialog: true } },
    });

    // Renaming only - no permissions checked.
    await wrapper.find('input.field-input').setValue('renamed-group');

    const saveBtn = wrapper.find('button.btn-primary');
    expect(saveBtn.attributes('disabled')).toBeUndefined();

    await saveBtn.trigger('click');
    await flushPromises();

    // Should not show a validation error, and should emit 'saved'.
    expect(wrapper.find('.save-error').exists()).toBe(false);
    expect(wrapper.emitted('saved')).toBeTruthy();

    const calledUrls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.map(c => c[0] as string);
    expect(calledUrls.some(u => u.includes('update_group') && u.includes('name=empty-group') && u.includes('newname=renamed-group'))).toBe(true);
  });

  it('blocks saving when the group name is blank, regardless of permissions', async () => {
    const group = new Group('some-group', [Permissions.admin]);
    globalThis.fetch = mockFetchRouter();

    const wrapper = mount(GroupPopup, {
      props: { group, allGroups: [group], isAdd: false },
      global: { stubs: { ConfirmDialog: true } },
    });

    await wrapper.find('input.field-input').setValue('   ');
    await wrapper.find('button.btn-primary').trigger('click');
    await flushPromises();

    expect(wrapper.find('.save-error').exists()).toBe(true);
    expect(wrapper.emitted('saved')).toBeFalsy();
  });

  it('keeps a checkbox for already-checked permissions after switching to a different module', async () => {
    // fileDrop belongs to the Global module.
    const group = new Group('mixed-group', [Permissions.fileDrop]);

    const wrapper = mount(GroupPopup, {
      props: { group, allGroups: [group], isAdd: false },
      global: { stubs: { ConfirmDialog: true } },
    });

    // Switch the module dropdown away from Global to Importer.
    const select = wrapper.find('select');
    await select.setValue('Importer');
    await select.trigger('change');

    // The group's existing Global permission must still be visible (with its
    // checkbox checked) so that it can be unchecked when moving the group to
    // a different module.
    expect(wrapper.text()).toContain(Permissions.fileDrop.friendlyName);
    const checkbox = wrapper
      .findAll('.perm-item input[type="checkbox"]')
      .find(cb => cb.element.closest('.perm-item')?.textContent?.includes(Permissions.fileDrop.friendlyName));
    expect(checkbox).toBeTruthy();
    expect((checkbox!.element as HTMLInputElement).checked).toBe(true);
  });

  it('allows unchecking a permission belonging to a different module than the one selected', async () => {
    const group = new Group('mixed-group', [Permissions.fileDrop]);

    const wrapper = mount(GroupPopup, {
      props: { group, allGroups: [group], isAdd: false },
      global: { stubs: { ConfirmDialog: true } },
    });

    const select = wrapper.find('select');
    await select.setValue('Importer');
    await select.trigger('change');

    const checkbox = wrapper
      .findAll('.perm-item input[type="checkbox"]')
      .find(cb => cb.element.closest('.perm-item')?.textContent?.includes(Permissions.fileDrop.friendlyName))!;

    await checkbox.setValue(false);

    // isDirty should now be true (permission set changed), enabling Save.
    const saveBtn = wrapper.find('button.btn-primary');
    expect(saveBtn.attributes('disabled')).toBeUndefined();
  });

  it('does not inherit a stale pre-selected group\'s module/permissions in add mode', async () => {
    // Simulates GroupList passing a previously-selected group as the 'group'
    // prop while isAdd=true (e.g. user selected a group, then clicked "+ Add Group").
    const staleGroup = new Group('old-group', [Permissions.admin]);
    globalThis.fetch = mockFetchRouter();

    const wrapper = mount(GroupPopup, {
      props: { group: staleGroup, allGroups: [staleGroup], isAdd: true },
      global: { stubs: { ConfirmDialog: true } },
    });

    // Name field must start blank, not 'old-group'.
    expect((wrapper.find('input.field-input').element as HTMLInputElement).value).toBe('');
    // Module select must start unselected, not inherit the stale group's module.
    expect((wrapper.find('select').element as HTMLSelectElement).value).toBe('');
    // No permission checkboxes should be pre-checked.
    const anyChecked = wrapper
      .findAll('.perm-item input[type="checkbox"]')
      .some(cb => (cb.element as HTMLInputElement).checked);
    expect(anyChecked).toBe(false);

    await wrapper.find('input.field-input').setValue('brand-new-group');
    await wrapper.find('select').setValue('Importer');
    await wrapper.find('button.btn-primary').trigger('click');
    await flushPromises();

    expect(wrapper.find('.save-error').exists()).toBe(false);
    expect(wrapper.emitted('saved')).toBeTruthy();

    const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
    const calledUrls = calls.map(c => c[0] as string);
    // Must create the brand new group...
    expect(calledUrls.some(u => u.includes('create_group') && u.includes('groupname=brand-new-group'))).toBe(true);
    // ...and must NOT touch/rename the stale old group.
    expect(calledUrls.some(u => u.includes('update_group'))).toBe(false);
    // The roles saved for the new group must be empty (admin's perm id '1' must not leak in).
    const rolesCall = calledUrls.find(u => u.includes('set_group_roles'));
    expect(rolesCall).toBeDefined();
    expect(rolesCall).not.toContain('roles=1');
  });

  it('marks the form dirty when only the module is changed while editing', async () => {
    const group = new Group('mixed-group', [Permissions.fileDrop]); // module = Global

    const wrapper = mount(GroupPopup, {
      props: { group, allGroups: [group], isAdd: false },
      global: { stubs: { ConfirmDialog: true } },
    });

    // No edits yet - Save should be disabled.
    expect(wrapper.find('button.btn-primary').attributes('disabled')).toBeDefined();

    // Change only the module - don't touch name or permission checkboxes.
    await wrapper.find('select').setValue('Importer');

    // Save should now be enabled, since the module selection changed.
    expect(wrapper.find('button.btn-primary').attributes('disabled')).toBeUndefined();
  });
});



