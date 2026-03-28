// ─── Low-level HTTP helpers & API calls ──────────────────────────────────────

import type {
  CheckResponse,
  DynamicPermissionsResponse,
  OAuthProvider,
  RawGroup,
  RawUser,
  UserPostData,
} from './types';

/** Read the API base URL from the <meta name="auth-api-url"> tag set in index.html.
 *  - When served by the Go binary directly, index.html has content="/" so calls go to /login etc.
 *  - When using the Vite dev server, the meta tag is absent so we fall back to /auth2/
 *    and the Vite proxy rewrites+forwards those to the Go backend on port 2003. */
function detectAuthURL(): string {
  if (typeof document !== 'undefined') {
    const meta = document.querySelector<HTMLMetaElement>('meta[name="auth-api-url"]');
    if (meta?.content) return meta.content.endsWith('/') ? meta.content : meta.content + '/';
  }
  return '/auth2/';
}

export let authBaseURL = detectAuthURL();

export function setAuthURL(url: string): void {
  authBaseURL = url;
}

function url(path: string): string {
  return authBaseURL + path;
}

function encodeParams(obj: Record<string, string | number | boolean | undefined>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null) {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
    }
  }
  return parts.join('&');
}

async function checkOk(res: Response): Promise<Response> {
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text || res.statusText);
  }
  return res;
}

// ─── Session ─────────────────────────────────────────────────────────────────

export async function login(identity: string, password: string): Promise<CheckResponse> {
  const res = await fetch(url('login'), {
    method: 'POST',
    headers: { Authorization: 'Basic ' + btoa(`${identity}:${password}`) },
  });
  await checkOk(res);
  return res.json();
}

export async function logout(): Promise<void> {
  await fetch(url('logout'), { method: 'POST' });
}

export async function check(): Promise<CheckResponse> {
  const res = await fetch(url('check'));
  await checkOk(res);
  return res.json();
}

export async function checkPassword(identity: string, password: string): Promise<string> {
  const res = await fetch(url('check_password'), {
    method: 'POST',
    headers: { Authorization: 'Basic ' + btoa(`${identity}:${password}`) },
  });
  await checkOk(res);
  return res.text();
}

export async function updatePassword(identity: string, oldPassword: string, newPassword: string): Promise<void> {
  const res = await fetch(`${url('update_password')}?${encodeParams({ email: identity })}`, {
    method: 'POST',
    headers: {
      'X-OldPassword': oldPassword,
      'X-NewPassword': newPassword,
    },
  });
  await checkOk(res);
}

export async function resetPasswordStart(email: string): Promise<void> {
  const res = await fetch(`${url('reset_password_start')}?${encodeParams({ email })}`, {
    method: 'POST',
  });
  await checkOk(res);
}

export async function resetPasswordFinish(userid: string, password: string, token: string): Promise<void> {
  const res = await fetch(`${url('reset_password_finish')}?${encodeParams({ userid })}`, {
    method: 'POST',
    headers: {
      'X-NewPassword': password,
      'X-ResetToken': token,
    },
  });
  await checkOk(res);
}

// ─── Users ───────────────────────────────────────────────────────────────────

export async function getUsers(includeArchived = false): Promise<RawUser[]> {
  const res = await fetch(`${url('userobjects')}?${encodeParams({ archived: includeArchived })}`);
  await checkOk(res);
  return res.json();
}

export async function createUser(data: UserPostData): Promise<void> {
  const res = await fetch(`${url('create_user')}?${encodeParams(data as unknown as Record<string, string>)}`, {
    method: 'PUT',
  });
  await checkOk(res);
}

export async function updateUser(data: UserPostData): Promise<void> {
  const res = await fetch(`${url('update_user')}?${encodeParams(data as unknown as Record<string, string>)}`, {
    method: 'POST',
  });
  await checkOk(res);
}

export async function archiveUser(userid: string): Promise<void> {
  const res = await fetch(`${url('archive_user')}?${encodeParams({ userid })}`, {
    method: 'POST',
  });
  await checkOk(res);
}

export async function unlockUser(userid: string, username: string): Promise<void> {
  const res = await fetch(`${url('unlock_user')}?${encodeParams({ userid, username })}`, {
    method: 'POST',
  });
  await checkOk(res);
}

export async function renameUser(oldIdentity: string, newIdentity: string, password: string): Promise<void> {
  const res = await fetch(`${url('rename_user')}?${encodeParams({ old: oldIdentity, new: newIdentity })}`, {
    method: 'POST',
    headers: { Authorization: 'Basic ' + btoa(`${oldIdentity}:${password}`) },
  });
  await checkOk(res);
}

export async function setUserGroups(userId: string, groups: string[]): Promise<void> {
  const res = await fetch(`${url('set_user_groups')}?${encodeParams({ userid: userId, groups: groups.join(',') })}`, {
    method: 'POST',
  });
  await checkOk(res);
}

// ─── Groups ──────────────────────────────────────────────────────────────────

export async function getGroups(): Promise<RawGroup[]> {
  const res = await fetch(url('groups'));
  await checkOk(res);
  return res.json();
}

export async function createGroup(groupName: string): Promise<void> {
  const res = await fetch(`${url('create_group')}?${encodeParams({ groupname: groupName })}`, {
    method: 'PUT',
  });
  await checkOk(res);
}

export async function updateGroup(name: string, newName: string): Promise<void> {
  const res = await fetch(`${url('update_group')}?${encodeParams({ name, newname: newName })}`, {
    method: 'POST',
  });
  await checkOk(res);
}

export async function deleteGroup(groupName: string): Promise<void> {
  const res = await fetch(`${url('delete_group')}?${encodeParams({ groupname: groupName })}`, {
    method: 'PUT',
  });
  await checkOk(res);
}

export async function setGroupRoles(groupName: string, roleIds: string[]): Promise<void> {
  const res = await fetch(`${url('set_group_roles')}?${encodeParams({ groupname: groupName, roles: roleIds.join(',') })}`, {
    method: 'PUT',
  });
  await checkOk(res);
}

// ─── Misc ────────────────────────────────────────────────────────────────────

export async function hasActiveDirectory(): Promise<number> {
  const res = await fetch(url('hasactivedirectory'));
  await checkOk(res);
  return res.json();
}

export async function getDynamicPermissions(): Promise<DynamicPermissionsResponse> {
  const res = await fetch(url('dynamic_permissions'));
  await checkOk(res);
  return res.json();
}

/** Returns the full static PermissionsTable as { "id": "name" } e.g. { "1": "admin", "1120": "watermoduleaccess" } */
export async function getGroupsPermNames(): Promise<Record<string, string>> {
  const res = await fetch(url('groups_perm_names'));
  await checkOk(res);
  return res.json();
}

export async function getOAuthProviders(): Promise<OAuthProvider[]> {
  const res = await fetch(url('oauth/providers'));
  await checkOk(res);
  return res.json();
}

