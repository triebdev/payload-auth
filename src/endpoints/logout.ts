import type { Endpoint, PayloadRequest } from 'payload'

import type { ResolvedAuthPluginOptions } from '../types'

import {
  buildClearCookieHeader,
  invalidateAllUserSessions,
  invalidateSession,
} from '../utilities/session'

/**
 * Creates the logout endpoints:
 * - POST /api/auth/logout         — logs out the current session
 * - POST /api/auth/logout-all     — logs out all sessions for the user
 */
export function createLogoutEndpoints(options: ResolvedAuthPluginOptions): Endpoint[] {
  return [
    {
      handler: async (req: PayloadRequest) => {
        const { payload } = req

        const refreshToken =
          req.headers?.get?.('cookie')?.match(/refresh-token=([^;]+)/)?.[1] || undefined

        try {
          // Invalidate the session in DB
          if (refreshToken) {
            await invalidateSession(payload, refreshToken, options.sessionsSlug)
          }

          // Clear cookies
          const headers = new Headers({ 'Content-Type': 'application/json' })
          headers.append(
            'Set-Cookie',
            buildClearCookieHeader('payload-token', options.cookieSecure),
          )
          headers.append(
            'Set-Cookie',
            buildClearCookieHeader('refresh-token', options.cookieSecure),
          )

          return new Response(JSON.stringify({ success: true }), { headers, status: 200 })
        } catch (error) {
          payload.logger.error({ err: error }, 'Logout failed')
          return Response.json({ error: 'Logout failed' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/logout',
    },
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        try {
          await invalidateAllUserSessions(payload, String(user.id), options.sessionsSlug)

          const headers = new Headers({ 'Content-Type': 'application/json' })
          headers.append(
            'Set-Cookie',
            buildClearCookieHeader('payload-token', options.cookieSecure),
          )
          headers.append(
            'Set-Cookie',
            buildClearCookieHeader('refresh-token', options.cookieSecure),
          )

          return new Response(JSON.stringify({ success: true }), { headers, status: 200 })
        } catch (error) {
          payload.logger.error({ err: error }, 'Logout all sessions failed')
          return Response.json({ error: 'Logout failed' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/logout-all',
    },
  ]
}
