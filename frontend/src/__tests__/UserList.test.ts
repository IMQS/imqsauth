import { describe, it, expect, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { User, Group } from '../services/auth';
import { AuthUserType } from '../services/types';
import { Permissions } from '../services/permissions';
import UserList from '../components/UserList.vue';
import { allModuleOptions } from '../services/modules';

// Give localStorage an admin role so isAdmin=true
import { storeSession } from '../services/auth';
storeSession({ Identity: 'admin@test.com', UserId: '1', InternalUUID: '', Roles: ['1'] });

function makeUser(overrides: Partial<User> = {}): User {
  const u = new User();
  u.userId       = '42';
  u.email        = 'alice@example.com';
  u.name         = 'Alice';
  u.surname      = 'Smith';
  u.authUserType = AuthUserType.IMQS;
  u.archived     = false;
  u.groups       = [];
  Object.assign(u, overrides);
  return u;
}

const modules = allModuleOptions();
const groups: Group[] = [];

describe('UserList', () => {
  it('renders user email in table', () => {
    const users = [makeUser()];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('alice@example.com');
  });

  it('shows loading message when loading=true and empty', () => {
    const wrapper = mount(UserList, {
      props: { users: [], groups, modules, loading: true },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('Loading');
  });

  it('shows empty message when no users and not loading', () => {
    const wrapper = mount(UserList, {
      props: { users: [], groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.text()).toContain('No users found');
  });

  it('filters users by search term', async () => {
    const users = [
      makeUser({ email: 'alice@example.com', name: 'Alice', surname: 'Smith' }),
      makeUser({ userId: '43', email: 'bob@example.com', name: 'Bob', surname: 'Jones' }),
    ];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    const input = wrapper.find('input.search-box');
    await input.setValue('bob');
    expect(wrapper.text()).toContain('bob@example.com');
    expect(wrapper.text()).not.toContain('alice@example.com');
  });

  it('filters out archived users in active mode', () => {
    const users = [
      makeUser({ archived: false }),
      makeUser({ userId: '99', email: 'archived@example.com', archived: true }),
    ];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    // default filter is 'active'
    expect(wrapper.text()).toContain('alice@example.com');
    expect(wrapper.text()).not.toContain('archived@example.com');
  });

  it('shows archived badge class on archived rows when filter=all', async () => {
    const users = [makeUser({ archived: true })];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    // Switch to "All" filter
    const radios = wrapper.findAll('input[type="radio"]');
    const allRadio = radios.find(r => (r.element as HTMLInputElement).value === 'all');
    await allRadio?.setValue('all');
    await allRadio?.trigger('change');

    const rows = wrapper.findAll('tr.archived');
    expect(rows.length).toBe(1);
  });

  it('selects user on row click', async () => {
    const users = [makeUser()];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    const row = wrapper.find('tbody tr');
    await row.trigger('click');
    expect(row.classes()).toContain('selected');
  });

  it('shows IMQS badge for IMQS user type', () => {
    const users = [makeUser({ authUserType: AuthUserType.IMQS })];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    expect(wrapper.find('.badge--imqs').exists()).toBe(true);
  });

  it('shows LDAP badge for LDAP user type', () => {
    const users = [makeUser({ authUserType: AuthUserType.LDAP })];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });
    const radios = wrapper.findAll('input[type="radio"]');
    // show all so LDAP user is visible
    expect(wrapper.find('.badge--ldap').exists()).toBe(true);
  });

  it('emits refresh after archive', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true, status: 200,
      json: () => Promise.resolve('ok'),
      text: () => Promise.resolve('ok'),
    }));

    const users = [makeUser()];
    const wrapper = mount(UserList, {
      props: { users, groups, modules, loading: false },
      global: { stubs: { UserPopup: true, ConfirmDialog: true, Teleport: true } },
    });

    // Select a user first
    await wrapper.find('tbody tr').trigger('click');
    // Trigger archive button
    await wrapper.find('.btn-danger').trigger('click');
    // ConfirmDialog is stubbed, directly call doArchive via the confirm emit
    await wrapper.findComponent({ name: 'ConfirmDialog' }).vm.$emit('confirm');
    // Drain all pending microtasks/promises from the async archive + fetch calls
    await flushPromises();

    expect(wrapper.emitted('refresh')).toBeDefined();
    vi.unstubAllGlobals();
  });
});

