import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// "esnext" avoids esbuild trying to down-level destructuring for old Safari targets
// (the error "Transforming destructuring to the configured target ... is not supported").
export default defineConfig({
  plugins: [react()],
  esbuild: { target: 'esnext' },
  optimizeDeps: { esbuildOptions: { target: 'esnext' } },
  build: { target: 'esnext', outDir: 'dist' },
  server: {
    port: 5173,
    // Forward API calls to the Flask server (python run.py -> http://127.0.0.1:5000)
    proxy: { '/api': { target: 'http://127.0.0.1:5000', changeOrigin: false } },
  },
});
