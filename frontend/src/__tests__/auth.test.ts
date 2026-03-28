import { describe, it, expect, beforeEach } from 'vitest';
import { Group, User, Model, storeSession, clearSession, isLoggedIn, hasLocalPermission, isLocalAdmin, getStoredIdentity } from '../services/auth';
import { AuthUserType } from '../services/types';
import { Permissions } from '../services/permissions';
import type { RawGroup, RawUser } from '../services/types';

// ── Group ─────────────────────────────────────────────────────────────────

describe('Group', () => {
  it('constructs with defaults', () => {
    const g = new Group('mygroup');
    expect(g.name).toBe('mygroup');
    expect(g.permissions).toEqual([]);
  });

  it('fromRaw parses name and role ids', () => {
    const g = new Group();
    const raw: RawGroup = { Name: 'admin', Roles: ['1', '2'], ID: '5' };
    g.fromRaw(raw);
    expect(g.name).toBe('admin');
    expect(g.permissions.length).toBe(2);
    expect(g.permissions[0].id).toBe('1');
    expect(g.permissions[1].id).toBe('2');
  });

  it('fromRaw ignores unknown role ids', () => {
    const g = new Group();
    g.fromRaw({ Name: 'test', Roles: ['99999'], ID: '1' });
    expect(g.permissions.length).toBe(0);
  });

  it('hasPermission returns true when permission present', () => {
    const g = new Group('test', [Permissions.admin]);
    expect(g.hasPermission(Permissions.admin)).toBe(true);
  });

  it('hasPermission returns false when permission absent', () => {
    const g = new Group('test', []);
    expect(g.hasPermission(Permissions.admin)).toBe(false);
  });
});

// ── User ──────────────────────────────────────────────────────────────────

const makeModel = (): Model => {
  const m = new Model();
  const adminGroup   = new Group(); adminGroup.fromRaw({ Name: 'admin',   Roles: ['1'], ID: '1' });
  const enabledGroup = new Group(); enabledGroup.fromRaw({ Name: 'enabled', Roles: ['2'], ID: '2' });
  m.groups = [adminGroup, enabledGroup];
  return m;
};

const rawUser: RawUser = {
  UserId: 42,
  Email: 'alice@example.com',
  Username: 'alice',
  Name: 'Alice',
  Surname: 'Smith',
  Mobile: '0821112222',
  Telephone: '0111234567',
  Remarks: 'test user',
  Created: '2024-01-01T00:00:00Z',
  CreatedBy: 'admin',
  Modified: '2024-06-01T00:00:00Z',
  ModifiedBy: 'admin',
  Archived: false,
  AccountLocked: false,
  AuthUserType: 0,
  Groups: ['admin', 'enabled'],
  LastLogin: '2025-01-01T00:00:00Z',
  EnabledDate: '2024-01-01T00:00:00Z',
  DisabledDate: '',
};

describe('User', () => {
  it('fromRaw populates all fields', () => {
    const model = makeModel();
    const u = new User();
    u.fromRaw(model, rawUser);
    expect(u.userId).toBe('42');
    expect(u.email).toBe('alice@example.com');
    expect(u.name).toBe('Alice');
    expect(u.surname).toBe('Smith');
    expect(u.authUserType).toBe(AuthUserType.IMQS);
    expect(u.groups.length).toBe(2);
  });

  it('displayName returns "Name Surname" when both set', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.displayName).toBe('Alice Smith');
  });

  it('displayName falls back to email', () => {
    const u = new User();
    u.email = 'test@example.com';
    expect(u.displayName).toBe('test@example.com');
  });

  it('isIMQSUser is true for AuthUserType.IMQS', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.isIMQSUser()).toBe(true);
    expect(u.isLDAPUser()).toBe(false);
  });

  it('isLDAPUser is true for AuthUserType.LDAP', () => {
    const model = makeModel();
    const u = new User();
    u.fromRaw(model, { ...rawUser, AuthUserType: 1 });
    expect(u.isLDAPUser()).toBe(true);
  });

  it('hasPermission checks transitively through groups', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.hasPermission(Permissions.admin)).toBe(true);
    expect(u.hasPermission(Permissions.enabled)).toBe(true);
  });

  it('hasGroup returns true for member group', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.hasGroup(model.groups[0])).toBe(true);
  });

  it('isAdmin is true when admin group present', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.isAdmin).toBe(true);
  });

  it('isEnabled is true when enabled group present', () => {
    const model = makeModel();
    const u = new User(); u.fromRaw(model, rawUser);
    expect(u.isEnabled).toBe(true);
  });

  it('archived user has archived flag', () => {
    const model = makeModel();
    const u = new User();
    u.fromRaw(model, { ...rawUser, Archived: true });
    expect(u.archived).toBe(true);
  });
});

// ── Model ─────────────────────────────────────────────────────────────────

describe('Model', () => {
  it('getGroupByName finds group', () => {
    const m = makeModel();
    expect(m.getGroupByName('admin')).toBeDefined();
    expect(m.getGroupByName('admin')?.name).toBe('admin');
  });

  it('getGroupByName returns undefined for missing group', () => {
    const m = makeModel();
    expect(m.getGroupByName('nonexistent')).toBeUndefined();
  });

  it('getUserByIdentity finds non-archived user by email', () => {
    const m = makeModel();
    const u = new User(); u.fromRaw(m, rawUser);
    m.users = [u];
    expect(m.getUserByIdentity('alice@example.com')).toBe(u);
  });

  it('getUserByIdentity does not return archived user', () => {
    const m = makeModel();
    const u = new User(); u.fromRaw(m, { ...rawUser, Archived: true });
    m.users = [u];
    expect(m.getUserByIdentity('alice@example.com')).toBeUndefined();
  });
});

// ── Session helpers ────────────────────────────────────────────────────────

describe('Session storage helpers', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('storeSession and getStoredIdentity roundtrip', () => {
    storeSession({ Identity: 'bob@example.com', UserId: '7', InternalUUID: 'uuid-1', Roles: ['1', '2'] });
    expect(getStoredIdentity()).toBe('bob@example.com');
  });

  it('clearSession removes stored data', () => {
    storeSession({ Identity: 'bob@example.com', UserId: '7', InternalUUID: 'uuid-1', Roles: ['1'] });
    clearSession();
    expect(getStoredIdentity()).toBeNull();
  });

  it('hasLocalPermission returns true when role stored', () => {
    storeSession({ Identity: 'bob', UserId: '7', InternalUUID: '', Roles: ['1', '2'] });
    expect(hasLocalPermission(Permissions.admin)).toBe(true);
    expect(hasLocalPermission(Permissions.enabled)).toBe(true);
  });

  it('hasLocalPermission returns false when role absent', () => {
    storeSession({ Identity: 'bob', UserId: '7', InternalUUID: '', Roles: ['2'] });
    expect(hasLocalPermission(Permissions.admin)).toBe(false);
  });

  it('isLocalAdmin returns true when admin role present', () => {
    storeSession({ Identity: 'alice', UserId: '1', InternalUUID: '', Roles: ['1'] });
    expect(isLocalAdmin()).toBe(true);
  });

  it('isLocalAdmin returns false when admin role absent', () => {
    storeSession({ Identity: 'bob', UserId: '2', InternalUUID: '', Roles: ['2'] });
    expect(isLocalAdmin()).toBe(false);
  });
});

