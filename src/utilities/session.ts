import type { Payload } from 'payload'

import type { ResolvedTokenConfig } from '../types'

import { DEFAULT_ACCESS_TOKEN_LIFETIME, DEFAULT_SESSION_LIFETIME } from '../types'
import { createTokenPreview } from './authLogger'
import { asLoosePayload } from './loosePayload'
import { generateDeviceFingerprint, generateSecureToken, signAccessToken } from './tokens'

interface CreateSessionInput {
  clientIp?: string
  payload: Payload
  /**
   * Slug of the sessions collection.
   * @default 'sessions'
   */
  sessionsSlug?: string
  tokenConfig?: ResolvedTokenConfig
  user: {
    applicationContext?: null | string
    email: string
    id: string
  }
  userAgent?: string
  /**
   * Collection slug embedded in the access token claims.
   * @default 'users'
   */
  usersSlug?: string
}

interface SessionResult {
  accessToken: string
  expiresAt: Date
  refreshToken: string
}

/**
 * Creates a new session (refresh token) and a corresponding access token.
 * The session is persisted in the sessions collection.
 */
export async function createSession(input: CreateSessionInput): Promise<SessionResult> {
  const { payload, sessionsSlug = 'sessions', tokenConfig, user, userAgent, usersSlug } = input

  const appContext = user.applicationContext || undefined
  const sessionLifetime =
    (appContext ? tokenConfig?.sessionLifetimes[appContext] : undefined) ??
    tokenConfig?.defaultSessionLifetime ??
    DEFAULT_SESSION_LIFETIME
  const accessTokenLifetime = tokenConfig?.accessTokenLifetime ?? DEFAULT_ACCESS_TOKEN_LIFETIME
  const expiresAt = new Date(Date.now() + sessionLifetime * 1000)
  const refreshToken = generateSecureToken()

  // Device fingerprint is derived from the User-Agent only (IP intentionally
  // excluded — see generateDeviceFingerprint). `clientIp` is still accepted by
  // this function for logging/auditing by callers but does not affect binding.
  const fingerprint = userAgent ? generateDeviceFingerprint(userAgent) : undefined

  await asLoosePayload(payload).create({
    collection: sessionsSlug,
    data: {
      deviceFingerprint: fingerprint,
      expiresAt: expiresAt.toISOString(),
      lastUsedAt: new Date().toISOString(),
      refreshToken,
      user: user.id,
      userAgent: userAgent || undefined,
    },
  })

  const accessToken = await signAccessToken(
    {
      id: user.id,
      applicationContext: appContext,
      collection: usersSlug,
      email: user.email,
    },
    accessTokenLifetime,
  )

  return { accessToken, expiresAt, refreshToken }
}

/**
 * Builds a Set-Cookie header string for auth cookies.
 * Used by endpoints that return Response directly.
 */
export function buildAuthCookieHeader(name: string, value: string, maxAge: number): string {
  const isProduction = process.env.NODE_ENV === 'production'
  return `${name}=${value}; HttpOnly; ${isProduction ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=${maxAge}`
}

/**
 * Builds a Set-Cookie header that clears an auth cookie.
 */
export function buildClearCookieHeader(name: string): string {
  return buildAuthCookieHeader(name, '', 0)
}

/**
 * Invalidates a session by deleting it from the database.
 */
export async function invalidateSession(
  payload: Payload,
  refreshToken: string,
  sessionsSlug: string = 'sessions',
): Promise<void> {
  const result = await asLoosePayload(payload).find({
    collection: sessionsSlug,
    limit: 1,
    where: { refreshToken: { equals: refreshToken } },
  })

  if (result.docs[0]) {
    await asLoosePayload(payload).delete({
      id: result.docs[0].id,
      collection: sessionsSlug,
    })
    payload.logger.info({ sessionId: result.docs[0].id }, 'Session invalidated')
  } else {
    payload.logger.warn(
      { refreshTokenPreview: createTokenPreview(refreshToken) },
      'Attempted to invalidate non-existent session',
    )
  }
}

/**
 * Invalidates all sessions for a user.
 */
export async function invalidateAllUserSessions(
  payload: Payload,
  userId: string,
  sessionsSlug: string = 'sessions',
): Promise<void> {
  await asLoosePayload(payload).delete({
    collection: sessionsSlug,
    where: { user: { equals: userId } },
  })
}

/**
 * Cleans up expired sessions. Can be called periodically (e.g. via cron).
 */
export async function cleanupExpiredSessions(
  payload: Payload,
  sessionsSlug: string = 'sessions',
): Promise<number> {
  const result = await asLoosePayload(payload).delete({
    collection: sessionsSlug,
    where: {
      expiresAt: { less_than: new Date().toISOString() },
    },
  })
  const count = Array.isArray(result.docs) ? result.docs.length : 0
  payload.logger.info({ count }, 'Expired sessions cleaned up')
  return count
}
