import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { lexicalEditor } from '@payloadcms/richtext-lexical'
import { MongoMemoryReplSet } from 'mongodb-memory-server'
import path from 'path'
import { buildConfig } from 'payload'
import sharp from 'sharp'
import { fileURLToPath } from 'url'

import { authPlugin } from '../src/index'
import { testEmailAdapter } from './helpers/testEmailAdapter.js'
import { seed } from './seed.js'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

if (!process.env.ROOT_DIR) {
  process.env.ROOT_DIR = dirname
}

if (!process.env.PAYLOAD_SECRET) {
  process.env.PAYLOAD_SECRET = 'dev-secret_key-payload-auth-min-32-chars'
}

const buildConfigWithMemoryDB = async () => {
  // Use an in-memory MongoDB replica set whenever no external connection string
  // is provided. This keeps the dev/test experience zero-config.
  const hasExternalDb = Boolean(process.env.DATABASE_URL || process.env.MONGODB_URI)
  if (!hasExternalDb) {
    // A single-node replica set still supports the multi-document
    // transactions Payload relies on, and starts faster / more reliably than a
    // 3-node set for local dev and tests.
    const memoryDB = await MongoMemoryReplSet.create({
      replSet: {
        count: 1,
        dbName: 'payloadmemory',
      },
    })

    process.env.DATABASE_URL = `${memoryDB.getUri()}&retryWrites=true`
    process.env.MONGODB_URI = process.env.DATABASE_URL
  } else {
    // Keep both env names in sync so downstream code can rely on either.
    if (!process.env.DATABASE_URL && process.env.MONGODB_URI) {
      process.env.DATABASE_URL = process.env.MONGODB_URI
    }
    if (!process.env.MONGODB_URI && process.env.DATABASE_URL) {
      process.env.MONGODB_URI = process.env.DATABASE_URL
    }
  }

  return buildConfig({
    admin: {
      importMap: {
        baseDir: path.resolve(dirname),
      },
    },
    collections: [
      {
        slug: 'users',
        admin: { useAsTitle: 'email' },
        auth: true,
        fields: [{ name: 'name', type: 'text' }],
      },
      {
        slug: 'posts',
        admin: { useAsTitle: 'title' },
        fields: [
          { name: 'title', type: 'text', required: true },
          { name: 'content', type: 'textarea' },
        ],
      },
      {
        slug: 'media',
        fields: [],
        upload: {
          staticDir: path.resolve(dirname, 'media'),
        },
      },
    ],
    db: mongooseAdapter({
      ensureIndexes: true,
      url: process.env.DATABASE_URL || '',
    }),
    editor: lexicalEditor(),
    email: testEmailAdapter,
    onInit: async (payload) => {
      await seed(payload)
    },
    plugins: [
      authPlugin({
        // Exercise application contexts: two frontends with different
        // session lifetimes and login paths.
        agentLogin: {
          // Dev/test-only fixed secret — the endpoint is also gated to
          // localhost hostnames, so this never carries risk outside the
          // zero-config dev/e2e sandbox.
          secret: 'dev-agent-login-secret',
        },
        contexts: {
          app: {
            loginPath: '/login',
            sessionLifetime: 30 * 24 * 60 * 60, // 30 days
          },
          backoffice: {
            email: {
              subject: 'Sign in to the back office',
            },
            loginPath: '/admin/login',
            sessionLifetime: 8 * 60 * 60, // 8 hours
          },
        },
        defaultContext: 'app',
        enableAgentLogin: true,
        rpName: 'Payload Auth Dev',
        serverURL: process.env.NEXT_PUBLIC_SERVER_URL || 'http://localhost:3000',
      }),
    ],
    secret: process.env.PAYLOAD_SECRET!,
    sharp,
    typescript: {
      outputFile: path.resolve(dirname, 'payload-types.ts'),
    },
  })
}

export default buildConfigWithMemoryDB()
