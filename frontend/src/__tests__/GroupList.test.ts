import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { Group } from '../services/auth';
import GroupList from '../components/GroupList.vue';
import { Permissions } from '../services/permissions';

function makeGroups(): Group[] {
  const adminGroup = new Group('admin', [Permissions.admin]);
  adminGroup.moduleName = 'Global';
  const enabledGroup = new Group('enabled', [Permissions.enabled]);
  enabledGroup.moduleName = 'Global';
  const roadsGroup = new Group('roads-viewer', []);
  roadsGroup.moduleName = 'Roads';
  return [adminGroup, enabledGroup, roadsGroup];
}

describe('GroupList', () => {
  it('renders group names', () => {
    const groups = makeGroups();
    const wrapper = mount(GroupList, {
      props: { groups, loading: false },
      global: { stubs: { GroupPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('admin');
    expect(wrapper.text()).toContain('enabled');
    expect(wrapper.text()).toContain('roads-viewer');
  });

  it('shows loading text when loading=true and no groups', () => {
    const wrapper = mount(GroupList, {
      props: { groups: [], loading: true },
      global: { stubs: { GroupPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('Loading');
  });

  it('shows empty message when no groups and not loading', () => {
    const wrapper = mount(GroupList, {
      props: { groups: [], loading: false },
      global: { stubs: { GroupPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('No groups found');
  });

  it('filters groups by search term', async () => {
    const groups = makeGroups();
    const wrapper = mount(GroupList, {
      props: { groups, loading: false },
      global: { stubs: { GroupPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    const searchInput = wrapper.find('input.search-box');
    await searchInput.setValue('roads');
    expect(wrapper.text()).toContain('roads-viewer');
    expect(wrapper.text()).not.toContain('admin');
  });

  it('shows permission detail when group selected', async () => {
    const groups = makeGroups();
    const wrapper = mount(GroupList, {
      props: { groups, loading: false },
      global: { stubs: { GroupPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    const firstItem = wrapper.find('.group-item');
    await firstItem.trigger('click');
    expect(wrapper.text()).toContain('Permissions');
  });
});

