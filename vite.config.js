import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // When deployed to GitHub Pages the site lives at:
  // https://keith-manville.github.io/logstory-orchestrator/
  // The base must match the repo name so asset paths resolve correctly.
  base: '/logstory-orchestrator/',
})
