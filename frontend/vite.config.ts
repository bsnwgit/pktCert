import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  // Relative asset paths — required for pkthub's proxy embed (Context
  // Viewer, Reg App Settings, NOC widgets) to work: pkthub can rewrite the
  // static index.html, but Vite's own runtime chunk/CSS preloading emits
  // absolute-path <link>/import() URLs at runtime that only a relative
  // `base` + the app's own <base href> in index.html can fix.
  base: './',
  plugins: [react()],
  server: {
    port: 5175,
    proxy: {
      '/api': {
        target: 'http://localhost:8763',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
