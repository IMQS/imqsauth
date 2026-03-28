// ─── Domain model ─────────────────────────────────────────────────────────────

import { getPermissionById, Permission, Permissions } from './permissions';
import { AuthUserType, authUserTypeFromNumber, type RawGroup, type RawUser } from './types';
import * as api from './api';

export { AuthUserType, authUserTypeFromNumber };

// ─── LocalStorage keys ───────────────────────────────────────────────────────

export const StorageKeys = {
  Identity:    'Identity',
  UserID:      'UserID',
  InternalUUID:'InternalUUID',
  UserRoles:   'UserRoles',
} as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Go's zero time.Time serialises as "0001-01-01T00:00:00Z". Treat it as absent. */
function zeroToUndef(d?: string): string | undefined {
  if (!d) return undefined;
  const year = new Date(d).getFullYear();
  return year <= 1 ? undefined : d;
}

// ─── Group ───────────────────────────────────────────────────────────────────

export class Group {
  name?: string;
  permissions: Permission[] = [];
  moduleName?: string;

  constructor(name?: string, permissions?: Permission[], moduleName?: string) {
    this.name        = name;
    this.permissions = permissions ?? [];
    this.moduleName  = moduleName;
  }

  fromRaw(raw: RawGroup): void {
    this.name = raw.Name;
    this.permissions = [];
    for (const roleId of (raw.Roles ?? [])) {
      const perm = getPermissionById(roleId);
      if (perm) this.permissions.push(perm);
    }
    // Infer module from the first permission that carries one
    if (!this.moduleName) {
      this.moduleName = this.permissions.find(p => p.module)?.module;
    }
  }

  hasPermission(perm: Permission): boolean {
    return this.permissions.some(p => p.id === perm.id);
  }
}

// ─── User ────────────────────────────────────────────────────────────────────

export class User {
  userId?: string;
  email?: string;
  username?: string;
  name?: string;
  surname?: string;
  mobileNumber?: string;
  telephoneNumber?: string;
  remarks?: string;
  modified?: string;
  modifiedBy?: string;
  created?: string;
  createdBy?: string;
  archived = false;
  accountLocked = false;
  groups: Group[] = [];
  authUserType: AuthUserType = AuthUserType.IMQS;
  lastLoginDate?: string;
  enabledDate?: string;
  disabledDate?: string;

  fromRaw(model: Model, raw: RawUser): void {
    this.email          = raw.Email;
    this.userId         = String(raw.UserId);   // Go sends int64 as a JSON number
    this.username       = raw.Username;
    this.name           = raw.Name;
    this.surname        = raw.Surname;
    this.mobileNumber   = raw.Mobile;
    this.telephoneNumber= raw.Telephone;
    this.remarks        = raw.Remarks;
    this.created        = raw.Created;
    this.createdBy      = raw.CreatedBy;
    this.modified       = raw.Modified;
    this.modifiedBy     = raw.ModifiedBy;
    this.archived       = raw.Archived;
    this.accountLocked  = raw.AccountLocked;
    this.authUserType   = authUserTypeFromNumber(raw.AuthUserType);
    this.lastLoginDate  = zeroToUndef(raw.LastLogin);
    this.enabledDate    = zeroToUndef(raw.EnabledDate);
    this.disabledDate   = zeroToUndef(raw.DisabledDate);
    this.groups         = [];
    for (const gname of (raw.Groups ?? [])) {
      const g = model.getGroupByName(gname);
      if (g) this.groups.push(g);
    }
  }

  get displayName(): string {
    if (this.name && this.surname) return `${this.name} ${this.surname}`;
    return this.email ?? this.username ?? '';
  }

  get identity(): string {
    return this.email ?? this.username ?? '';
  }

  isIMQSUser():  boolean { return this.authUserType === AuthUserType.IMQS; }
  isLDAPUser():  boolean { return this.authUserType === AuthUserType.LDAP; }
  isOAuthUser(): boolean { return this.authUserType === AuthUserType.OAuth; }
  isMSAADUser(): boolean { return this.authUserType === AuthUserType.MSAAD; }

  hasGroup(group: Group): boolean {
    return this.groups.some(g => g.name === group.name);
  }

  hasPermission(perm: Permission): boolean {
    return this.groups.some(g => g.hasPermission(perm));
  }

  get isEnabled(): boolean     { return this.hasPermission(Permissions.enabled); }
  get isAdmin(): boolean       { return this.hasPermission(Permissions.admin); }
}

// ─── Model ───────────────────────────────────────────────────────────────────

export class Model {
  users:  User[]  = [];
  groups: Group[] = [];

  async build(): Promise<void> {
    const [rawGroups, rawUsers] = await Promise.all([
      api.getGroups(),
      api.getUsers(true),
    ]);

    this.groups = rawGroups.map(rg => {
      const g = new Group();
      g.fromRaw(rg);
      return g;
    }).sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''));

    this.users = rawUsers.map(ru => {
      const u = new User();
      u.fromRaw(this, ru);
      return u;
    }).sort(compareUsers);
  }

  getGroupByName(name: string): Group | undefined {
    return this.groups.find(g => g.name === name);
  }

  getUserByIdentity(identity: string): User | undefined {
    return this.users.find(u => !u.archived && (u.username === identity || u.email === identity));
  }
}

function compareUsers(a: User, b: User): number {
  const aKey = (a.isIMQSUser() ? a.email : a.username) ?? '';
  const bKey = (b.isIMQSUser() ? b.email : b.username) ?? '';
  return aKey.toLowerCase().localeCompare(bKey.toLowerCase());
}

// ─── Session helpers ─────────────────────────────────────────────────────────

export function getStoredIdentity(): string | null    { return localStorage.getItem(StorageKeys.Identity); }
export function getStoredUserId(): string | null      { return localStorage.getItem(StorageKeys.UserID); }
export function getStoredUUID(): string | null        { return localStorage.getItem(StorageKeys.InternalUUID); }

export function storeSession(data: { Identity: string; UserId: string; InternalUUID: string; Roles: string[] }): void {
  localStorage.setItem(StorageKeys.Identity,     data.Identity);
  localStorage.setItem(StorageKeys.UserID,       data.UserId);
  localStorage.setItem(StorageKeys.InternalUUID, data.InternalUUID);
  localStorage.setItem(StorageKeys.UserRoles,    btoa(data.Roles.join(',')));
}

export function clearSession(): void {
  localStorage.removeItem(StorageKeys.Identity);
  localStorage.removeItem(StorageKeys.UserID);
  localStorage.removeItem(StorageKeys.InternalUUID);
  localStorage.removeItem(StorageKeys.UserRoles);
  // Clear all cookies
  for (const cookie of document.cookie.split(';')) {
    const name = cookie.split('=')[0].trim();
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
}

export function isLoggedIn(): boolean {
  return document.cookie.split(';').some(c => c.trim().startsWith('session='));
}

// ─── User permission helpers (local, from localStorage cache) ────────────────

export function getLocalRoles(): string[] {
  const raw = localStorage.getItem(StorageKeys.UserRoles);
  if (!raw) return [];
  try { return atob(raw).split(','); } catch { return []; }
}

export function hasLocalPermission(perm: Permission): boolean {
  return getLocalRoles().includes(perm.id);
}

export function isLocalAdmin(): boolean {
  return hasLocalPermission(Permissions.admin);
}

