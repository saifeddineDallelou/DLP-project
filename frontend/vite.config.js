import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.js',
    // Components under test are all in src/; there is no reason to walk
    // node_modules or the build output looking for specs.
    include: ['src/**/*.test.{js,jsx}'],
  },
});
