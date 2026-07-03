import type { PayloadRequest } from 'payload'

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { resolveOptions } from '../types'
import { generateDeviceFingerprint } from '../utilities/tokens'
import { createRefreshEndpoints } from './refresh'

const TEST_SECRET = 'test-secret-for-payload-auth-unit-tests-min-32-chars'

beforeAll(() => {
  vi.stubEnv('PAYLOAD_SECRET', TEST_SECRET)
})

afterAll(() => {
  vi.unstubAllEnvs()
})

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.runAllTimers()
  vi.useRealTimers()
})

const mockOptions = resolveOptions({
  allowedOrigins: ['http://localhost:3006'],
  enableAgentLogin: false,
  enableMagicLink: true,
  enableOAuth: true,
  enableWebAuthn: true,
  rpID: 'localhost',
  rpName: 'Test App',
  serverURL: 'http://localhost:3006',
  tokens: {
    accessTokenLifetime: 900,
    magicLinkValidity: 900,
  },
})

describe('createRefreshEndpoints /auth/refresh', () => {
  it('should return endpoint array with /auth/refresh', () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    expect(endpoints).toHaveLength(1)
    expect(endpoints[0].path).toBe('/auth/refresh')
    expect(endpoints[0].method).toBe('post')
  })

  it('should return 400 when refresh token is missing in cookie', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockReq = {
      headers: new Headers(),
      payload: {
        logger: {
          error: vi.fn(),
          info: vi.fn(),
          warn: vi.fn(),
        },
      },
    } as unknown as PayloadRequest

    const response = await handler(mockReq)
    expect(response.status).toBe(400)
    const body = await response.json()
    expect(body.error).toBe('refresh token is required')
  })

  it('should successfully refresh and return a new access token when a valid session is found', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockSession = {
      id: 'session-123',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'valid-refresh-token',
      user: {
        id: 'user-456',
        applicationContext: undefined,
        email: 'test@example.com',
      },
    }

    const mockFind = vi.fn().mockResolvedValue({
      docs: [mockSession],
    })
    const mockUpdate = vi.fn().mockResolvedValue({
      id: 'session-123',
    })

    const mockReq = {
      headers: new Headers({
        cookie: 'refresh-token=valid-refresh-token',
      }),
      payload: {
        find: mockFind,
        logger: {
          error: vi.fn(),
          info: vi.fn(),
          warn: vi.fn(),
        },
        update: mockUpdate,
      },
    } as unknown as PayloadRequest

    const response = await handler(mockReq)
    expect(response.status).toBe(200)

    const body = await response.json()
    expect(body.user.id).toBe('user-456')
    expect(body.user.email).toBe('test@example.com')

    const setCookie = response.headers.get('Set-Cookie')
    expect(setCookie).toContain('payload-token=')
    expect(setCookie).toContain('HttpOnly')

    expect(mockFind).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'sessions',
        where: expect.objectContaining({
          refreshToken: { equals: 'valid-refresh-token' },
        }),
      }),
    )
    expect(mockUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'session-123',
        collection: 'sessions',
        data: expect.objectContaining({
          lastUsedAt: expect.any(String),
        }),
      }),
    )
  })

  it('should return 401 when session is not found or expired', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockFind = vi.fn().mockResolvedValue({
      docs: [],
    })

    const mockReq = {
      headers: new Headers({
        cookie: 'refresh-token=expired-refresh-token',
      }),
      payload: {
        find: mockFind,
        logger: {
          error: vi.fn(),
          info: vi.fn(),
          warn: vi.fn(),
        },
      },
    } as unknown as PayloadRequest

    const response = await handler(mockReq)
    expect(response.status).toBe(401)
    const body = await response.json()
    expect(body.error).toBe('Invalid or expired refresh token')
  })

  it('should return 401 and delete session when the User-Agent fingerprint mismatches', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    // Fingerprint of a completely different browser/User-Agent.
    const storedFingerprint = generateDeviceFingerprint('Firefox/OriginalBrowser')

    const mockSession = {
      id: 'session-fingerprint-mismatch',
      deviceFingerprint: storedFingerprint,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'some-refresh-token',
      user: {
        id: 'user-456',
        applicationContext: undefined,
        email: 'test@example.com',
      },
    }

    const mockFind = vi.fn().mockResolvedValue({ docs: [mockSession] })
    const mockDelete = vi.fn().mockResolvedValue({ id: 'session-fingerprint-mismatch' })

    const mockReq = {
      headers: new Headers({
        cookie: 'refresh-token=some-refresh-token',
        'user-agent': 'Chrome/DifferentBrowser',
        'x-forwarded-for': '1.2.3.4',
      }),
      payload: {
        delete: mockDelete,
        find: mockFind,
        logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
      },
    } as unknown as PayloadRequest

    const response = await handler(mockReq)
    expect(response.status).toBe(401)
    const body = await response.json()
    expect(body.error).toBe('Invalid session - device mismatch')

    expect(mockDelete).toHaveBeenCalledWith({
      id: 'session-fingerprint-mismatch',
      collection: 'sessions',
    })
  })

  it('should SUCCEED when the same User-Agent refreshes from a different IP (regression)', async () => {
    // The catastrophic false-logout case: same browser, different IP.
    // The fingerprint is UA-only, so the IP change must NOT invalidate it.
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    // Session was created on IPv6 loopback...
    const storedFingerprint = generateDeviceFingerprint(userAgent)

    const mockSession = {
      id: 'session-same-ua-diff-ip',
      deviceFingerprint: storedFingerprint,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'valid-refresh-token',
      user: {
        id: 'user-789',
        applicationContext: undefined,
        email: 'user@example.com',
      },
    }

    const mockFind = vi.fn().mockResolvedValue({ docs: [mockSession] })
    const mockUpdate = vi.fn().mockResolvedValue({ id: 'session-same-ua-diff-ip' })
    const mockDelete = vi.fn()

    const mockReq = {
      headers: new Headers({
        cookie: 'refresh-token=valid-refresh-token',
        'user-agent': userAgent,
        // ...but now refreshes from a DIFFERENT IP (e.g. 127.0.0.1 vs ::1).
        'x-forwarded-for': '127.0.0.1',
      }),
      payload: {
        delete: mockDelete,
        find: mockFind,
        logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        update: mockUpdate,
      },
    } as unknown as PayloadRequest

    const response = await handler(mockReq)

    // Must NOT log out: refresh succeeds and the session is preserved.
    expect(response.status).toBe(200)
    expect(mockDelete).not.toHaveBeenCalled()
    expect(mockUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'session-same-ua-diff-ip', collection: 'sessions' }),
    )
    const body = await response.json()
    expect(body.user.id).toBe('user-789')
  })

  it('deduplicates concurrent refresh requests for the same token into a single DB call', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockSession = {
      id: 'session-dedup',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'shared-refresh-token',
      user: {
        id: 'user-dedup',
        applicationContext: undefined,
        email: 'dedup@example.com',
      },
    }

    let resolveFind: (v: unknown) => void = () => {}
    const mockFind = vi.fn().mockReturnValue(
      new Promise((resolve) => {
        resolveFind = resolve
      }),
    )
    const mockUpdate = vi.fn().mockResolvedValue({ id: 'session-dedup' })

    const createReq = () =>
      ({
        headers: new Headers({ cookie: 'refresh-token=shared-refresh-token' }),
        payload: {
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
          update: mockUpdate,
        },
      }) as unknown as PayloadRequest

    const p1 = handler(createReq())
    const p2 = handler(createReq())

    // Release the single in-flight DB lookup.
    resolveFind({ docs: [mockSession] })

    const [res1, res2] = await Promise.all([p1, p2])

    // Only ONE database call despite two concurrent requests.
    expect(mockFind).toHaveBeenCalledTimes(1)
    expect(res1.status).toBe(200)
    expect(res2.status).toBe(200)

    const body1 = await res1.json()
    const body2 = await res2.json()
    expect(body1.user.id).toBe('user-dedup')
    expect(body2.user.id).toBe('user-dedup')
  })

  it('reuses the same response within the grace period after settlement', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockSession = {
      id: 'session-grace',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'grace-refresh-token',
      user: {
        id: 'user-grace',
        applicationContext: undefined,
        email: 'grace@example.com',
      },
    }

    const mockFind = vi.fn().mockResolvedValue({ docs: [mockSession] })
    const mockUpdate = vi.fn().mockResolvedValue({ id: 'session-grace' })

    const createReq = () =>
      ({
        headers: new Headers({ cookie: 'refresh-token=grace-refresh-token' }),
        payload: {
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
          update: mockUpdate,
        },
      }) as unknown as PayloadRequest

    // First request performs the actual refresh.
    const res1 = await handler(createReq())
    expect(res1.status).toBe(200)

    // Second request within grace period should reuse the cached response.
    const res2 = await handler(createReq())
    expect(res2.status).toBe(200)

    // Still only ONE database call.
    expect(mockFind).toHaveBeenCalledTimes(1)
  })

  it('regression: grace-period second request succeeds after first response body is consumed', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockSession = {
      id: 'session-consumed-body',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'consumed-body-token',
      user: {
        id: 'user-consumed',
        applicationContext: undefined,
        email: 'consumed@example.com',
      },
    }

    const mockFind = vi.fn().mockResolvedValue({ docs: [mockSession] })
    const mockUpdate = vi.fn().mockResolvedValue({ id: 'session-consumed-body' })

    const createReq = () =>
      ({
        headers: new Headers({ cookie: 'refresh-token=consumed-body-token' }),
        payload: {
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
          update: mockUpdate,
        },
      }) as unknown as PayloadRequest

    // First request — consume the body the way Payload/Next.js would when sending the HTTP response.
    const res1 = await handler(createReq())
    expect(res1.status).toBe(200)
    await res1.json() // body is now consumed (bodyUsed === true)

    // Second request arrives within the grace period.
    // Before the fix this throws: "Response.clone: Body has already been consumed."
    const res2 = await handler(createReq())
    expect(res2.status).toBe(200)

    const body2 = await res2.json()
    expect(body2.user.id).toBe('user-consumed')
    expect(body2.user.email).toBe('consumed@example.com')

    // Deduplication still holds — only one DB lookup.
    expect(mockFind).toHaveBeenCalledTimes(1)
  })

  it('regression: concurrent second response body is readable after first is consumed', async () => {
    const endpoints = createRefreshEndpoints(mockOptions)
    const handler = endpoints[0].handler

    const mockSession = {
      id: 'session-concurrent-consumed',
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      refreshToken: 'concurrent-consumed-token',
      user: {
        id: 'user-concurrent',
        applicationContext: undefined,
        email: 'concurrent@example.com',
      },
    }

    let resolveFind: (v: unknown) => void = () => {}
    const mockFind = vi.fn().mockReturnValue(
      new Promise((resolve) => {
        resolveFind = resolve
      }),
    )
    const mockUpdate = vi.fn().mockResolvedValue({ id: 'session-concurrent-consumed' })

    const createReq = () =>
      ({
        headers: new Headers({ cookie: 'refresh-token=concurrent-consumed-token' }),
        payload: {
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
          update: mockUpdate,
        },
      }) as unknown as PayloadRequest

    const p1 = handler(createReq())
    const p2 = handler(createReq())

    resolveFind({ docs: [mockSession] })

    const [res1, res2] = await Promise.all([p1, p2])

    expect(res1.status).toBe(200)
    expect(res2.status).toBe(200)

    // Simulate Payload consuming res1's body first (the originator response).
    // Before the fix, res2 is a .clone() of the same consumed object → throws.
    const body1 = await res1.json()
    const body2 = await res2.json()

    expect(body1.user.id).toBe('user-concurrent')
    expect(body2.user.id).toBe('user-concurrent')

    expect(mockFind).toHaveBeenCalledTimes(1)
  })
})
