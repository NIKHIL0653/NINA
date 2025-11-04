import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist/server',
    rollupOptions: {
      input: 'server/index.ts',
      output: {
        entryFileNames: 'node-build.mjs',
        format: 'es'
      }
    },
    ssr: true,
    minify: false,
    target: 'node18'
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./client"),
      "@shared": path.resolve(__dirname, "./shared"),
    },
  },
})