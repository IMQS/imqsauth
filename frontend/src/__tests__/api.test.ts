import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setAuthURL } from '../services/api';
import * as api from '../services/api';

// Mock fetch helper
function mockFetch(status: number, body: unknown) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(text),
  });
}

beforeEach(() => {
  setAuthURL('/auth2/');
  vi.restoreAllMocks();
});

describe('api.login', () => {
  it('posts to /auth2/login with Basic auth header', async () => {
    const payload = { UserId: '1', Identity: 'alice', Email: '', Username: '', Roles: ['1'], InternalUUID: '' };
    globalThis.fetch = mockFetch(200, payload);

    const result = await api.login('alice', 'secret');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      '/auth2/login',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ Authorization: 'Basic ' + btoa('alice:secret') }),
      }),
    );
    expect(result.Identity).toBe('alice');
  });

  it('throws on non-200 response', async () => {
    globalThis.fetch = mockFetch(401, 'Unauthorized');
    await expect(api.login('bad', 'creds')).rejects.toThrow('Unauthorized');
  });
});

describe('api.check', () => {
  it('calls GET /auth2/check', async () => {
    const payload = { UserId: '5', Identity: 'bob', Email: 'bob@test.com', Username: '', Roles: ['2'], InternalUUID: '' };
    globalThis.fetch = mockFetch(200, payload);
    const res = await api.check();
    expect(res.UserId).toBe('5');
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('/auth2/check');
  });
});

describe('api.getUsers', () => {
  it('calls GET /auth2/userobjects?archived=false', async () => {
    globalThis.fetch = mockFetch(200, []);
    await api.getUsers(false);
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toContain('/auth2/userobjects');
    expect(calledUrl).toContain('archived=false');
  });

  it('calls GET /auth2/userobjects?archived=true when includeArchived=true', async () => {
    globalThis.fetch = mockFetch(200, []);
    await api.getUsers(true);
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toContain('archived=true');
  });
});

describe('api.getGroups', () => {
  it('calls GET /auth2/groups', async () => {
    globalThis.fetch = mockFetch(200, []);
    await api.getGroups();
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0]).toBe('/auth2/groups');
  });
});

describe('api.createUser', () => {
  it('calls PUT /auth2/create_user with query params', async () => {
    globalThis.fetch = mockFetch(200, 'ok');
    await api.createUser({
      email: 'new@test.com',
      firstname: 'New',
      lastname: 'User',
      mobilenumber: '0821111111',
    });
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const opts = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(calledUrl).toContain('/auth2/create_user');
    expect(calledUrl).toContain('email=new%40test.com');
    expect(opts.method).toBe('PUT');
  });
});

describe('api.createGroup', () => {
  it('calls PUT /auth2/create_group', async () => {
    globalThis.fetch = mockFetch(200, 'ok');
    await api.createGroup('my-group');
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toContain('/auth2/create_group');
    expect(calledUrl).toContain('groupname=my-group');
  });
});

describe('api.archiveUser', () => {
  it('calls POST /auth2/archive_user', async () => {
    globalThis.fetch = mockFetch(200, 'ok');
    await api.archiveUser('123');
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const opts = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(calledUrl).toContain('/auth2/archive_user');
    expect(calledUrl).toContain('userid=123');
    expect(opts.method).toBe('POST');
  });
});

describe('api.setGroupRoles', () => {
  it('calls PUT /auth2/set_group_roles with comma-separated ids', async () => {
    globalThis.fetch = mockFetch(200, 'ok');
    await api.setGroupRoles('my-group', ['1', '2', '300']);
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toContain('/auth2/set_group_roles');
    expect(calledUrl).toContain('groupname=my-group');
    expect(calledUrl).toContain('roles=1%2C2%2C300');
  });
});

describe('api.resetPasswordStart', () => {
  it('calls POST /auth2/reset_password_start with email', async () => {
    globalThis.fetch = mockFetch(200, 'ok');
    await api.resetPasswordStart('user@example.com');
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toContain('/auth2/reset_password_start');
    expect(calledUrl).toContain('email=user%40example.com');
  });
});

describe('api URL configuration', () => {
  it('setAuthURL changes the base URL', async () => {
    setAuthURL('http://localhost:8080/auth2/');
    globalThis.fetch = mockFetch(200, []);
    await api.getGroups();
    const calledUrl: string = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(calledUrl).toBe('http://localhost:8080/auth2/groups');
    setAuthURL('/auth2/');
  });
});

