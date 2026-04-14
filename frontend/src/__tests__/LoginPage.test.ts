import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import LoginPage from '../components/LoginPage.vue';

function mockFetchLogin(ok: boolean) {
  const loginPayload = ok
    ? { UserId: '1', Identity: 'alice', Email: 'alice@test.com', Username: '', Roles: ['1'], InternalUUID: '' }
    : 'Unauthorized';
  return vi.fn().mockImplementation((url: string) => {
    // providers call — return empty array so oauthProviders stays []
    if (String(url).includes('providers')) {
      return Promise.resolve({
        ok: true, status: 200, statusText: 'OK',
        json: () => Promise.resolve([]),
        text: () => Promise.resolve('[]'),
      });
    }
    // login call
    return Promise.resolve({
      ok,
      status: ok ? 200 : 401,
      statusText: ok ? 'OK' : 'Unauthorized',
      json: () => Promise.resolve(loginPayload),
      text: () => Promise.resolve(ok ? JSON.stringify(loginPayload) : loginPayload),
    });
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('LoginPage redirect', () => {
  it('emits logged-in when no redirect param', async () => {
    // No ?redirect in URL
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      ...window.location, search: '', origin: 'http://localhost',
    } as Location);
    globalThis.fetch = mockFetchLogin(true);

    const wrapper = mount(LoginPage, { global: { stubs: { Teleport: true } } });
    await wrapper.find('#identity').setValue('alice@test.com');
    await wrapper.find('#password').setValue('secret');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.emitted('logged-in')).toBeDefined();
  });

  it('navigates to same-origin redirect on success', async () => {
    vi.spyOn(window, 'location', 'get').mockReturnValue({
      ...window.location,
      search: '?redirect=http%3A%2F%2Flocalhost%2Fdashboard',
      origin: 'http://localhost',
    } as Location);
    const assignSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...window.location, href: '', search: '?redirect=http%3A%2F%2Flocalhost%2Fdashboard', origin: 'http://localhost' },
    });
    globalThis.fetch = mockFetchLogin(true);

    const wrapper = mount(LoginPage, { global: { stubs: { Teleport: true } } });
    await wrapper.find('#identity').setValue('alice@test.com');
    await wrapper.find('#password').setValue('secret');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    // logged-in is NOT emitted when redirecting
    expect(wrapper.emitted('logged-in')).toBeUndefined();
    expect(window.location.href).toBe('http://localhost/dashboard');
  });

  it('allows same-host redirect on a different port', async () => {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...window.location, href: 'http://localhost:2003/ui/', search: '?redirect=http%3A%2F%2Flocalhost%3A80%2Fauth%2Fcallback', origin: 'http://localhost:2003', hostname: 'localhost' },
    });
    globalThis.fetch = mockFetchLogin(true);

    const wrapper = mount(LoginPage, { global: { stubs: { Teleport: true } } });
    await wrapper.find('#identity').setValue('alice@test.com');
    await wrapper.find('#password').setValue('secret');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.emitted('logged-in')).toBeUndefined();
    // Browser normalises http://localhost:80 → http://localhost (port 80 is implicit)
    expect(window.location.href).toBe('http://localhost/auth/callback');
  });

  it('ignores cross-host redirect param', async () => {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...window.location, href: 'http://localhost/', search: '?redirect=http%3A%2F%2Fevil.com%2Fphish', origin: 'http://localhost', hostname: 'localhost' },
    });
    globalThis.fetch = mockFetchLogin(true);

    const wrapper = mount(LoginPage, { global: { stubs: { Teleport: true } } });
    await wrapper.find('#identity').setValue('alice@test.com');
    await wrapper.find('#password').setValue('secret');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    // Falls back to emitting logged-in, href unchanged
    expect(wrapper.emitted('logged-in')).toBeDefined();
    expect(window.location.href).not.toContain('evil.com');
  });

  it('shows error on failed login', async () => {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...window.location, href: 'http://localhost/', search: '', origin: 'http://localhost' },
    });
    globalThis.fetch = mockFetchLogin(false);

    const wrapper = mount(LoginPage, { global: { stubs: { Teleport: true } } });
    await wrapper.find('#identity').setValue('alice@test.com');
    await wrapper.find('#password').setValue('wrong');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.find('.error-msg').exists()).toBe(true);
    expect(wrapper.emitted('logged-in')).toBeUndefined();
  });
});



