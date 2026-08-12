import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/authorize': 'http://127.0.0.1:5000',
      '/oauth': 'http://127.0.0.1:5000',
      '/api': 'http://127.0.0.1:5000',
      '/delete-all-posts': 'http://127.0.0.1:5000',
      '/me': 'http://127.0.0.1:5000',
      '/token': 'http://127.0.0.1:5000',
      '/refresh': 'http://127.0.0.1:5000',
      '/logout': 'http://127.0.0.1:5000',
      '/tweet': 'http://127.0.0.1:5000',
      '/tweet-media': 'http://127.0.0.1:5000'
    }
  }
})
