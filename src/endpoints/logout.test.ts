import type { PayloadRequest } from 'payload'

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { resolveOptions } from '../types'
import { createLogoutEndpoints } from './logout'

beforeAll(() => {
  vi.stubEnv('PAYLOAD_SECRET', 'test-secret-for-payload-auth-unit-tests-min-32-chars')
})

afterAll(() => {
  vi.unstubAllEnvs()
})

const mockOptions = resolveOptions({ serverURL: 'http://localhost:3006' })

describe('createLogoutEndpoints', () => {
  it('should return two endpoints: /auth/logout and /auth/logout-all', () => {
    const endpoints = createLogoutEndpoints(mockOptions)
    expect(endpoints).toHaveLength(2)
    expect(endpoints.map((e) => e.path)).toEqual(['/auth/logout', '/auth/logout-all'])
    expect(endpoints.every((e) => e.method === 'post')).toBe(true)
  })

  describe('/auth/logout', () => {
    it('should invalidate the session and clear cookies when a refresh token is present', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const mockFind = vi.fn().mockResolvedValue({ docs: [{ id: 'session-1' }] })
      const mockDelete = vi.fn().mockResolvedValue({ id: 'session-1' })

      const mockReq = {
        headers: new Headers({ cookie: 'refresh-token=some-refresh-token' }),
        payload: {
          delete: mockDelete,
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)

      expect(mockDelete).toHaveBeenCalledWith(
        expect.objectContaining({ id: 'session-1', collection: 'sessions' }),
      )

      const setCookies =
        response.headers.getSetCookie ?
          response.headers.getSetCookie()
        : [response.headers.get('Set-Cookie')]
      const joined = setCookies.join(';')
      expect(joined).toContain('payload-token=')
      expect(joined).toContain('refresh-token=')
      expect(joined).toContain('Max-Age=0')
    })

    it('should succeed and clear cookies even without a refresh token cookie', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const mockReq = {
        headers: new Headers(),
        payload: {
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)
    })

    it('should return 500 when session invalidation throws', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[0].handler

      const mockFind = vi.fn().mockRejectedValue(new Error('db down'))

      const mockReq = {
        headers: new Headers({ cookie: 'refresh-token=some-refresh-token' }),
        payload: {
          find: mockFind,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(500)
      const body = await response.json()
      expect(body.error).toBe('Logout failed')
    })
  })

  describe('/auth/logout-all', () => {
    it('should return 401 when no authenticated user is present', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[1].handler

      const mockReq = {
        payload: {
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
        user: null,
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(401)
      const body = await response.json()
      expect(body.error).toBe('Authentication required')
    })

    it('should invalidate all sessions for the authenticated user and clear cookies', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[1].handler

      const mockDelete = vi.fn().mockResolvedValue({ docs: [] })

      const mockReq = {
        payload: {
          delete: mockDelete,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
        user: { id: 'user-1' },
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(200)
      const body = await response.json()
      expect(body.success).toBe(true)

      expect(mockDelete).toHaveBeenCalledWith({
        collection: 'sessions',
        where: { user: { equals: 'user-1' } },
      })
    })

    it('should return 500 when session invalidation throws', async () => {
      const endpoints = createLogoutEndpoints(mockOptions)
      const handler = endpoints[1].handler

      const mockDelete = vi.fn().mockRejectedValue(new Error('db down'))

      const mockReq = {
        payload: {
          delete: mockDelete,
          logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
        },
        user: { id: 'user-1' },
      } as unknown as PayloadRequest

      const response = await handler(mockReq)
      expect(response.status).toBe(500)
      const body = await response.json()
      expect(body.error).toBe('Logout failed')
    })
  })
})
