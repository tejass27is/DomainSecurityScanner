import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const spaHtmlFallback = (req) => {
  const accept = req.headers.accept || ''
  return accept.includes('text/html') ? '/index.html' : undefined
}

const clientRoutes = new Set([
  '/', '/auth', '/admin', '/vapt', '/vapt/reports', '/vapt-upload',
  '/scan-dashboard', '/scan-details', '/scan', '/history', '/malware',
  '/malware-history', '/malware-dashboard', '/assessment', '/profile',
])

function clientRouteFallback() {
  const indexPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'index.html')
  return {
    name: 'client-route-fallback',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const pathname = (req.url || '').split('?')[0]
        const acceptsHtml = (req.headers.accept || '').includes('text/html')
        if (req.method === 'GET' && acceptsHtml && clientRoutes.has(pathname)) {
          try {
            const html = await server.transformIndexHtml(req.url || '/', fs.readFileSync(indexPath, 'utf-8'))
            res.statusCode = 200
            res.setHeader('Content-Type', 'text/html')
            res.end(html)
            return
          } catch (error) {
            next(error)
            return
          }
        }
        next()
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [clientRouteFallback(), react()],
  server: {
    proxy: {
      // Proxy all backend API routes through the Vite dev server.
      // This eliminates CORS issues in development because the browser
      // talks to the same origin (localhost:5173) and Vite forwards
      // requests to the actual backend at 127.0.0.1:8000.
      // SPA page refreshes (e.g. /admin, /auth) should still resolve to index.html,
      // while JSON API calls continue to go to the backend.
      '/auth': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/scanner': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/assessment': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/score': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/fix': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/admin': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/webhooks': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
        bypass: spaHtmlFallback,
      },
      '/malware': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/report-issue': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/vapt': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/healthz': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
      '/public': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        bypass: spaHtmlFallback,
      },
    },
  },
})
