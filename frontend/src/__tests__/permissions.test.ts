import { describe, it, expect, beforeEach } from 'vitest';
import { Permission, Permissions, permissionsArray, applyDynamicPermissions, getPermissionById } from '../services/permissions';
import { AuthModule, authModuleExists, allModuleOptions } from '../services/modules';

describe('Permission', () => {
  it('creates with correct fields', () => {
    const p = new Permission('1', 'admin', 'Administrator', 'Super-user', AuthModule.GLOBAL);
    expect(p.id).toBe('1');
    expect(p.name).toBe('admin');
    expect(p.friendlyName).toBe('Administrator');
    expect(p.module).toBe(AuthModule.GLOBAL);
  });

  it('throws for unknown module', () => {
    expect(() => new Permission('999', 'test', 'Test', 'desc', 'NONEXISTENT_MODULE')).toThrow();
  });
});

describe('Permissions registry', () => {
  it('contains admin permission with id 1', () => {
    expect(Permissions.admin.id).toBe('1');
    expect(Permissions.admin.module).toBe(AuthModule.GLOBAL);
  });

  it('contains enabled permission with id 2', () => {
    expect(Permissions.enabled.id).toBe('2');
  });

  it('getPermissionById finds by id', () => {
    const p = getPermissionById('1');
    expect(p).toBeDefined();
    expect(p?.name).toBe('admin');
  });

  it('getPermissionById returns undefined for unknown id', () => {
    expect(getPermissionById('99999')).toBeUndefined();
  });

  it('permissionsArray is populated', () => {
    expect(permissionsArray.length).toBeGreaterThan(0);
  });
});

describe('applyDynamicPermissions', () => {
  it('adds a new dynamic permission', () => {
    const before = permissionsArray.length;
    applyDynamicPermissions({
      dynamic: [{
        id: '20000',
        name: 'testDynamic',
        friendly: 'Test Dynamic',
        description: 'A dynamic perm',
        module: 'Global',
      }],
    });
    expect(permissionsArray.length).toBe(before + 1);
    expect(Permissions.testDynamic).toBeDefined();
    expect(Permissions.testDynamic.id).toBe('20000');

    // Cleanup
    delete Permissions.testDynamic;
    permissionsArray.splice(permissionsArray.findIndex(p => p.name === 'testDynamic'), 1);
  });

  it('skips dynamic permissions with id < 15000', () => {
    const before = permissionsArray.length;
    applyDynamicPermissions({
      dynamic: [{ id: '100', name: 'badDynamic', friendly: 'Bad', description: '', module: 'Global' }],
    });
    expect(permissionsArray.length).toBe(before);
  });

  it('relabels an existing permission', () => {
    const orig = Permissions.admin.friendlyName;
    applyDynamicPermissions({
      relabel: [{ id: '1', name: 'admin', friendly: 'Super Admin', description: 'Updated' }],
    });
    expect(Permissions.admin.friendlyName).toBe('Super Admin');
    // Restore
    Permissions.admin.friendlyName = orig;
  });
});

describe('AuthModule', () => {
  it('GLOBAL resolves to Global', () => {
    expect(AuthModule.GLOBAL).toBe('Global');
  });

  it('authModuleExists returns true for known module', () => {
    expect(authModuleExists('Global')).toBe(true);
  });

  it('authModuleExists returns false for unknown module', () => {
    expect(authModuleExists('NONEXISTENT')).toBe(false);
  });

  it('allModuleOptions returns sorted list', () => {
    const opts = allModuleOptions();
    expect(opts.length).toBeGreaterThan(0);
    expect(opts[0].id).toBeDefined();
    expect(opts[0].value).toBeDefined();
    // Check sorted
    for (let i = 1; i < opts.length; i++) {
      expect(opts[i].value.localeCompare(opts[i - 1].value)).toBeGreaterThanOrEqual(0);
    }
  });
});

