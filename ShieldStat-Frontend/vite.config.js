import { defineConfig, loadEnv } from 'vite'
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
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  if (command === 'build' && !env.VITE_BACKEND_URL?.trim()) {
    throw new Error('VITE_BACKEND_URL must be set when building the production frontend.')
  }

  if (command === 'serve' && !env.VITE_DEV_PROXY_TARGET?.trim()) {
    throw new Error('VITE_DEV_PROXY_TARGET or VITE_BACKEND_URL must be set when running the dev server.')
  }

  const devProxyTarget = env.VITE_DEV_PROXY_TARGET?.trim() || env.VITE_BACKEND_URL?.trim()

  return {
    plugins: [clientRouteFallback(), react()],
    server: {
      proxy: {
        // Proxy all backend API routes through the Vite dev server.
        // This eliminates CORS issues in development because the browser
        // talks to the same origin (localhost:5173) and Vite forwards
        // requests to the actual backend.
        // SPA page refreshes (e.g. /admin, /auth) should still resolve to index.html,
        // while JSON API calls continue to go to the backend.
        '/auth': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/scanner': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/assessment': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/score': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/fix': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/admin': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/webhooks': {
          target: devProxyTarget,
          changeOrigin: true,
          ws: true,
          bypass: spaHtmlFallback,
        },
        '/malware': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/report-issue': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/vapt': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/webscan': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/health': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/healthz': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
        '/public': {
          target: devProxyTarget,
          changeOrigin: true,
          bypass: spaHtmlFallback,
        },
      },
    },
  }
})
