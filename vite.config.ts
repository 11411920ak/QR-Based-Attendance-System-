import build from '@hono/vite-build/cloudflare-pages'
import devServer from '@hono/vite-dev-server'
import adapter from '@hono/vite-dev-server/cloudflare'
import basicSsl from '@vitejs/plugin-basic-ssl'
import { defineConfig } from 'vite'

const useHttps = process.env.VITE_HTTPS === 'true'

export default defineConfig({
  plugins: [
    ...(useHttps ? [basicSsl()] : []),
    build(),
    devServer({
      adapter,
      entry: 'src/index.tsx'
    })
  ],
  server: {
    https: useHttps ? {} : undefined,
  }
})
