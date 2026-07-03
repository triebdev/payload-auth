import type { Payload, PayloadRequest } from 'payload'

import { getPayload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import config from '../../dev/payload.config'
import { createMagicLinkEndpoints } from '../../src/endpoints/magic-link'
import { resolveOptions } from '../../src/types'
import { asLoosePayload } from '../../src/utilities/loosePayload'
import { cleanupExpiredSessions, createSession } from '../../src/utilities/session'

let payload: Payload

function makeRequest(body: unknown): PayloadRequest {
  return {
    headers: new Headers(),
    json: async () => body,
    payload,
  } as unknown as PayloadRequest
}

beforeAll(async () => {
  payload = await getPayload({ config })
})

afterAll(async () => {
  await payload.destroy?.()
})

describe('authPlugin against a real Payload + Mongo instance', () => {
  it('registers the webauthn-credentials and sessions collections', () => {
    const slugs = payload.config.collections.map((c) => c.slug)
    expect(slugs).toContain('webauthn-credentials')
    expect(slugs).toContain('sessions')
  })

  it('extends the users collection with plugin fields', () => {
    const users = payload.config.collections.find((c) => c.slug === 'users')
    const fieldNames = (users?.fields || []).map((f) => ('name' in f ? f.name : undefined))
    expect(fieldNames).toEqual(
      expect.arrayContaining(['applicationContext', 'socialAccounts', 'lastLoginAt']),
    )
  })

  it('auto-creates a user on first magic-link request and persists it', async () => {
    const options = resolveOptions({ contexts: { app: {} } })
    const endpoints = createMagicLinkEndpoints(options)
    const requestEndpoint = endpoints.find((e) => e.path === '/auth/magic-link/request')!

    const email = 'int-test-user@example.com'
    const response = await requestEndpoint.handler(makeRequest({ email }))
    expect(response.status).toBe(200)

    const result = await asLoosePayload(payload).find({
      collection: 'users',
      where: { email: { equals: email } },
    })
    expect(result.docs).toHaveLength(1)
  })

  it('creates and cleans up a real session document', async () => {
    const created = await asLoosePayload(payload).create({
      collection: 'users',
      data: { email: 'session-int-test@example.com' },
    })

    await createSession({
      payload,
      sessionsSlug: 'sessions',
      tokenConfig: {
        accessTokenLifetime: 900,
        defaultSessionLifetime: -1, // already expired
        magicLinkValidity: 900,
        sessionLifetimes: {},
      },
      user: { id: String(created.id), email: created.email as string },
      usersSlug: 'users',
    })

    const before = await asLoosePayload(payload).find({ collection: 'sessions' })
    expect(before.docs.length).toBeGreaterThan(0)

    const deletedCount = await cleanupExpiredSessions(payload, 'sessions')
    expect(deletedCount).toBeGreaterThan(0)
  })
})
