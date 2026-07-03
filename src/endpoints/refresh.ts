import type { Endpoint, PayloadRequest } from 'payload'

import type { ResolvedAuthPluginOptions } from '../types'

import {
  createTokenPreview,
  logAuthError,
  logAuthSuccess,
  logAuthWarning,
  logRateLimitViolation,
  logTokenValidationFailure,
} from '../utilities/authLogger'
import { AuthErrors, handleError } from '../utilities/errorResponses'
import { getClientIp } from '../utilities/getClientIp'
import { asLoosePayload, type LooseDoc } from '../utilities/loosePayload'
import { refreshRateLimit } from '../utilities/rateLimit'
import { buildAuthCookieHeader } from '../utilities/session'
import { generateDeviceFingerprint, signAccessToken } from '../utilities/tokens'

// Structured result of a successful refresh — stored in the dedup map so
// each caller can build its own fresh Response (a shared Response object
// would have its body consumed by the first caller, breaking .clone() for
// all subsequent callers in the grace period).
type RefreshResult = {
  cookieHeader: string
  email: string
  userId: string
}

// Thrown by performRefresh for known auth failures (invalid token, device
// mismatch, …) so the handler can return the exact error response without
// going through the generic 500 path.
class RefreshAuthError extends Error {
  constructor(public readonly response: Response) {
    super('RefreshAuthError')
    this.name = 'RefreshAuthError'
  }
}

function buildRefreshResponse(result: RefreshResult): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' })
  headers.append('Set-Cookie', result.cookieHeader)
  return new Response(JSON.stringify({ user: { id: result.userId, email: result.email } }), {
    headers,
    status: 200,
  })
}

// In-flight + recently-completed refresh deduplication.
// When a browser sends multiple parallel requests after the access token
// expires, every request would otherwise trigger a separate refresh. We
// coalesce all concurrent requests into a single token generation. After
// settlement we keep the entry for a short grace period so that rapid
// follow-up requests (e.g. SSE reconnects, asset fetches) receive the same
// token without generating a new one.
const refreshDeduplication = new Map<string, Promise<RefreshResult>>()
const GRACE_PERIOD_MS = 2000

/**
 * Creates the token refresh/revalidate endpoint:
 * - POST /api/auth/refresh — refreshes an expired access token using a valid refresh token
 */
export function createRefreshEndpoints(options: ResolvedAuthPluginOptions): Endpoint[] {
  return [
    {
      handler: async (req: PayloadRequest) => {
        const { payload } = req

        // Apply rate limiting
        const rateLimitResult = await refreshRateLimit(req)
        if (!rateLimitResult.success) {
          logRateLimitViolation(
            payload,
            '/auth/refresh',
            getClientIp(req) || 'unknown',
            rateLimitResult.resetTime,
          )
          return AuthErrors.rateLimited(rateLimitResult.resetTime)
        }

        // Extract refresh token from cookie
        const refreshToken =
          req.headers?.get?.('cookie')?.match(/refresh-token=([^;]+)/)?.[1] || undefined

        if (!refreshToken) {
          logAuthWarning(payload, 'Refresh token missing in request cookie', {
            clientIp: getClientIp(req),
          })
          return AuthErrors.tokenRequired('refresh token')
        }

        try {
          // Check for an in-flight or recently-completed refresh for this token.
          const existing = refreshDeduplication.get(refreshToken)
          if (existing) {
            const result = await existing
            return buildRefreshResponse(result)
          }

          const promise = performRefresh(payload, refreshToken, options, req)
          refreshDeduplication.set(refreshToken, promise)

          // Keep the entry for a short grace period after settlement so rapid
          // follow-up requests (before the browser has stored the new cookie)
          // still receive the same response instead of generating another token.
          // .finally() re-throws on rejection; chain .catch() to suppress the
          // resulting unhandled-rejection when no subsequent request reads the
          // cached entry (error is handled by each awaiting caller above).
          promise
            .finally(() => {
              setTimeout(() => refreshDeduplication.delete(refreshToken), GRACE_PERIOD_MS)
            })
            .catch(() => {})

          const result = await promise
          return buildRefreshResponse(result)
        } catch (error) {
          if (error instanceof RefreshAuthError) {
            return error.response
          }
          logAuthError(payload, 'Token refresh endpoint unhandled error', error, {
            clientIp: getClientIp(req),
            tokenPreview: refreshToken ? createTokenPreview(refreshToken) : undefined,
          })
          return handleError(error, payload, 'Token refresh failed', 'Token refresh failed')
        }
      },
      method: 'post',
      path: '/auth/refresh',
    },
  ]
}

async function performRefresh(
  payload: PayloadRequest['payload'],
  refreshToken: string,
  options: ResolvedAuthPluginOptions,
  req: PayloadRequest,
): Promise<RefreshResult> {
  // Find valid session
  const sessionResult = await asLoosePayload(payload).find({
    collection: options.sessionsSlug,
    depth: 1,
    limit: 1,
    where: {
      expiresAt: { greater_than: new Date().toISOString() },
      refreshToken: { equals: refreshToken },
    },
  })

  const sessionDoc = sessionResult.docs[0]
  if (!sessionDoc) {
    logTokenValidationFailure(
      payload,
      'refresh token',
      'Session not found or expired',
      refreshToken,
    )
    throw new RefreshAuthError(AuthErrors.invalidToken('refresh token'))
  }

  // User is populated at depth:1
  const user = (
    typeof sessionDoc.user === 'object' && sessionDoc.user !== null ?
      sessionDoc.user
    : await asLoosePayload(payload).findByID({
        id: sessionDoc.user as string,
        collection: options.usersSlug,
      })) as LooseDoc

  if (!user) {
    logAuthError(
      payload,
      'User not found for valid refresh token',
      new Error('User resolution failed'),
      {
        sessionId: String(sessionDoc.id),
        userId:
          typeof sessionDoc.user === 'string' ?
            sessionDoc.user
          : String((sessionDoc.user as { id: number | string }).id),
      },
    )
    throw new RefreshAuthError(AuthErrors.invalidToken('refresh token'))
  }

  // Sign new access token in Payload-compatible format
  let newToken: string
  try {
    newToken = await signAccessToken(
      {
        id: String(user.id),
        applicationContext: user.applicationContext as string | undefined,
        collection: options.usersSlug,
        email: user.email as string,
      },
      options.tokens.accessTokenLifetime,
    )
  } catch (error) {
    logAuthError(payload, 'Failed to sign new access token during refresh', error, {
      sessionId: String(sessionDoc.id),
      userId: String(user.id),
    })
    throw error
  }

  // Validate device fingerprint for security (User-Agent only — IP is not part
  // of the fingerprint; see generateDeviceFingerprint).
  const clientIp = getClientIp(req)
  const userAgent = req.headers?.get('user-agent') || undefined
  const currentFingerprint = userAgent ? generateDeviceFingerprint(userAgent) : null

  if (
    sessionDoc.deviceFingerprint &&
    currentFingerprint &&
    sessionDoc.deviceFingerprint !== currentFingerprint
  ) {
    payload.logger.warn(
      {
        actualFingerprint: currentFingerprint,
        expectedFingerprint: sessionDoc.deviceFingerprint,
        sessionId: sessionDoc.id,
        userId: sessionDoc.user,
      },
      'Device fingerprint mismatch during token refresh',
    )

    // Invalidate the session as it may be compromised
    await asLoosePayload(payload).delete({
      id: sessionDoc.id,
      collection: options.sessionsSlug,
    })

    throw new RefreshAuthError(AuthErrors.deviceMismatch())
  }

  try {
    await asLoosePayload(payload).update({
      id: sessionDoc.id,
      collection: options.sessionsSlug,
      data: { lastUsedAt: new Date().toISOString() },
    })
  } catch (error) {
    logAuthError(payload, 'Failed to update session lastUsedAt during refresh', error, {
      sessionId: String(sessionDoc.id),
      userId: String(user.id),
    })
  }

  logAuthSuccess(payload, 'Token refresh successful', {
    clientIp,
    sessionId: String(sessionDoc.id),
    userId: String(user.id),
  })

  return {
    cookieHeader: buildAuthCookieHeader(
      'payload-token',
      newToken,
      options.tokens.accessTokenLifetime,
      options.cookieSecure,
    ),
    email: user.email as string,
    userId: String(user.id),
  }
}
