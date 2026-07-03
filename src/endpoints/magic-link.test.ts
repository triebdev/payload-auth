import type { PayloadRequest } from 'payload'

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { resolveOptions } from '../types'
import { createMagicLinkEndpoints } from './magic-link'

beforeAll(() => {
  vi.stubEnv('PAYLOAD_SECRET', 'test-secret-for-payload-auth-unit-tests-min-32-chars')
})

afterAll(() => {
  vi.unstubAllEnvs()
})

const mockOptions = resolveOptions({ serverURL: 'http://localhost:3006' })

// Each test uses its own unique client IP so the module-level in-memory rate
// limiter in ../utilities/rateLimit does not leak state across test cases.
let ipCounter = 0
function uniqueIp(): string {
  ipCounter += 1
  return `10.0.0.${ipCounter}`
}

function makeReq(
  body: unknown,
  overrides: { headers?: Record<string, string>; payload?: Record<string, unknown> } = {},
): PayloadRequest {
  return {
    headers: new Headers({ 'x-forwarded-for': uniqueIp(), ...overrides.headers }),
    json: async () => body,
    payload: {
      create: vi.fn(),
      find: vi.fn().mockResolvedValue({ docs: [] }),
      logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
      sendEmail: vi.fn().mockResolvedValue(undefined),
      ...overrides.payload,
    },
  } as unknown as PayloadRequest
}

describe('createMagicLinkEndpoints', () => {
  it('should return /auth/magic-link/request and /auth/magic-link/verify', () => {
    const endpoints = createMagicLinkEndpoints(mockOptions)
    expect(endpoints.map((e) => e.path)).toEqual([
      '/auth/magic-link/request',
      '/auth/magic-link/verify',
    ])
    expect(endpoints.every((e) => e.method === 'post')).toBe(true)
  })

  describe('/auth/magic-link/request', () => {
    it('should return success:true and send an email for a known user', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const existingUser = { id: 'user-1', email: 'user@example.com' }
      const mockSendEmail = vi.fn().mockResolvedValue(undefined)
      const req = makeReq(
        { email: 'user@example.com' },
        {
          payload: {
            find: vi.fn().mockResolvedValue({ docs: [existingUser] }),
            sendEmail: mockSendEmail,
          },
        },
      )

      const response = await handler(req)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    it('anti-enumeration: returns success:true even for an unknown user when autoCreateUsers is disabled', async () => {
      const options = resolveOptions({
        magicLink: { autoCreateUsers: false },
        serverURL: 'http://localhost:3006',
      })
      const endpoints = createMagicLinkEndpoints(options)
      const handler = endpoints[0].handler

      const mockCreate = vi.fn()
      const req = makeReq(
        { email: 'unknown@example.com' },
        {
          payload: {
            create: mockCreate,
            find: vi.fn().mockResolvedValue({ docs: [] }),
          },
        },
      )

      const response = await handler(req)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(mockCreate).not.toHaveBeenCalled()
    })

    it('anti-enumeration: returns success:true even when the request handler throws internally', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const req = makeReq(
        { email: 'user@example.com' },
        {
          payload: {
            find: vi.fn().mockRejectedValue(new Error('db unavailable')),
          },
        },
      )

      const response = await handler(req)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    it('auto-create: creates a new user when autoCreateUsers is enabled (default) and none exists', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const mockCreate = vi.fn().mockResolvedValue({ id: 'new-user', email: 'newuser@example.com' })
      const req = makeReq(
        { email: 'newuser@example.com' },
        {
          payload: {
            create: mockCreate,
            find: vi.fn().mockResolvedValue({ docs: [] }),
          },
        },
      )

      const response = await handler(req)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          collection: 'users',
          data: expect.objectContaining({ email: 'newuser@example.com' }),
        }),
      )
    })

    it('should reject an invalid email with 400', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const req = makeReq({ email: 'not-an-email' })

      const response = await handler(req)
      expect(response.status).toBe(400)
    })

    it('should enforce rate limiting after the configured number of requests', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const ip = uniqueIp()
      const makeFixedIpReq = () =>
        ({
          headers: new Headers({ 'x-forwarded-for': ip }),
          json: async () => ({ email: 'ratelimit@example.com' }),
          payload: {
            create: vi.fn(),
            find: vi
              .fn()
              .mockResolvedValue({ docs: [{ id: 'user-1', email: 'ratelimit@example.com' }] }),
            logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
            sendEmail: vi.fn().mockResolvedValue(undefined),
          },
        }) as unknown as PayloadRequest

      // magicLinkRateLimit allows 5 requests per 15 minute window.
      let lastResponse
      for (let i = 0; i < 6; i++) {
        lastResponse = await handler(makeFixedIpReq())
      }

      expect(lastResponse!.status).toBe(429)
      const body = await lastResponse!.json()
      expect(body.error).toBe('Too many requests')
    })
  })

  describe('/auth/magic-link/verify', () => {
    it('should return 400 when token is missing', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[1].handler

      const req = makeReq({})
      const response = await handler(req)
      expect(response.status).toBe(400)
    })

    it('should return 401 for an invalid/unparseable token', async () => {
      const endpoints = createMagicLinkEndpoints(mockOptions)
      const handler = endpoints[1].handler

      const req = makeReq({ token: 'not-a-valid-jwt' })
      const response = await handler(req)
      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error).toBe('Invalid or expired magic link')
    })
  })
})
