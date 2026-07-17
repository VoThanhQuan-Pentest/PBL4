import { defineConfig } from 'vite';

export default defineConfig({
  publicDir: 'public',
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8080',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]'
      }
    }
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.js'],
    coverage: {
      provider: 'v8',
      include: ['src/core/**/*.js'],
      exclude: ['src/**/*.test.js'],
      reporter: ['text', 'json-summary', 'lcov'],
      // Browser-bound legacy/main.js is exercised by Playwright and has static
      // regression checks. Security-critical logic is extracted into core so
      // it is measurable here; new shared input/DOM/cache/order helpers cannot
      // reduce this floor in CI.
      thresholds: {
        statements: 85,
        branches: 73,
        functions: 83,
        lines: 85
      }
    }
  }
});
