import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  // Use a relative base so that asset paths in index.html are relative (./assets/…).
  // This makes the SPA work regardless of the exact path Apache proxies it from,
  // with no dependency on Apache forwarding /auth/ui/assets/ separately.
  base: './',
  build: {
    outDir: '../httpfront/static',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // Stable chunk names for Go embed
        entryFileNames: 'assets/[name].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Proxy API calls to the running Go backend during development.
      // Port 2003 matches testconf/imqsauth.json.
      // The rewrite strips /auth2 because Go registers routes without that prefix (/login, not /auth2/login).
      '/auth2': {
        target: 'http://localhost:2003',
        changeOrigin: true,
        rewrite: (path: string) => path.replace(/^\/auth2/, ''),
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/__tests__/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
    },
  },
});

