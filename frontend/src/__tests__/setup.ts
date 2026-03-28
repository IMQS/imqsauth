// Global test setup
import { vi } from 'vitest';

// Stub fetch globally — individual tests can override with vi.stubGlobal / fetchMock
globalThis.fetch = vi.fn();

// Stub localStorage
const store: Record<string, string> = {};
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    getItem:    (k: string) => store[k] ?? null,
    setItem:    (k: string, v: string) => { store[k] = v; },
    removeItem: (k: string) => { delete store[k]; },
    clear:      () => { Object.keys(store).forEach(k => delete store[k]); },
  },
  writable: true,
});

// Stub document.cookie for isLoggedIn
Object.defineProperty(document, 'cookie', {
  writable: true,
  value: '',
});

