import type { PayloadRequest } from 'payload'

/**
 * Centralized authentication logging utility.
 * Ensures consistent logging format for all authentication events.
 */

export interface AuthLogContext {
  [key: string]: unknown
  clientIp?: string
  email?: string
  errorCode?: string
  provider?: string
  sessionId?: string
  tokenPreview?: string
  userAgent?: string
  userId?: string
}

/**
 * Logs successful authentication events
 */
export function logAuthSuccess(
  payload: PayloadRequest['payload'],
  event: string,
  context: AuthLogContext = {},
): void {
  payload.logger.info(context, `Auth success: ${event}`)
}

/**
 * Logs authentication warnings (suspicious but not necessarily malicious)
 */
export function logAuthWarning(
  payload: PayloadRequest['payload'],
  event: string,
  context: AuthLogContext = {},
): void {
  payload.logger.warn(context, `Auth warning: ${event}`)
}

/**
 * Logs authentication errors (failures, invalid tokens, etc.)
 */
export function logAuthError(
  payload: PayloadRequest['payload'],
  event: string,
  error: unknown,
  context: AuthLogContext = {},
): void {
  payload.logger.error(
    {
      err: error instanceof Error ? error : new Error(String(error)),
      ...context,
    },
    `Auth error: ${event}`,
  )
}

/**
 * Logs security-related events (potential attacks, violations)
 */
export function logSecurityEvent(
  payload: PayloadRequest['payload'],
  event: string,
  severity: 'critical' | 'high' | 'low' | 'medium',
  context: AuthLogContext = {},
): void {
  const message = `Security event [${severity.toUpperCase()}]: ${event}`

  switch (severity) {
    case 'critical':
    case 'high':
      payload.logger.error(context, message)
      break
    case 'low':
      payload.logger.info(context, message)
      break
    case 'medium':
      payload.logger.warn(context, message)
      break
  }
}

/**
 * Creates a safe token preview for logging (first 8 chars)
 */
export function createTokenPreview(token: string): string {
  if (!token || typeof token !== 'string') {
    return 'invalid'
  }
  return token.length > 8 ? token.substring(0, 8) + '...' : token
}

/**
 * Extracts common context from request for logging
 */
export function extractLogContext(req: PayloadRequest): AuthLogContext {
  const clientIp =
    req.headers?.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers?.get('x-real-ip')?.trim() ||
    req.headers?.get('cf-connecting-ip')?.trim() ||
    'unknown'

  return {
    clientIp,
    userAgent: req.headers?.get('user-agent') || 'unknown',
  }
}

/**
 * Logs token validation failures with appropriate context
 */
export function logTokenValidationFailure(
  payload: PayloadRequest['payload'],
  tokenType: string,
  reason: string,
  token?: string,
  additionalContext: AuthLogContext = {},
): void {
  logAuthError(payload, `Token validation failed`, reason, {
    tokenPreview: token ? createTokenPreview(token) : undefined,
    tokenType,
    ...additionalContext,
  })
}

/**
 * Logs rate limiting violations
 */
export function logRateLimitViolation(
  payload: PayloadRequest['payload'],
  endpoint: string,
  clientIdentifier: string,
  resetTime?: number,
): void {
  logSecurityEvent(payload, 'Rate limit exceeded', 'medium', {
    clientIdentifier,
    endpoint,
    resetTime: resetTime ? new Date(resetTime).toISOString() : undefined,
  })
}

/**
 * Logs device fingerprint mismatches
 */
export function logDeviceFingerprintMismatch(
  payload: PayloadRequest['payload'],
  sessionId: string,
  userId: string,
  expectedFingerprint: string,
  actualFingerprint: string,
  clientIp: string,
): void {
  logSecurityEvent(payload, 'Device fingerprint mismatch', 'high', {
    actualFingerprint: createTokenPreview(actualFingerprint),
    clientIp,
    expectedFingerprint: createTokenPreview(expectedFingerprint),
    sessionId,
    userId,
  })
}

/**
 * Logs session lifecycle events
 */
export function logSessionEvent(
  payload: PayloadRequest['payload'],
  event: 'cleaned_up' | 'created' | 'expired' | 'invalidated' | 'refreshed',
  context: { sessionId: string } & AuthLogContext,
): void {
  logAuthSuccess(payload, `Session ${event}`, context)
}

/**
 * Logs OAuth events
 */
export function logOAuthEvent(
  payload: PayloadRequest['payload'],
  event: 'email_unverified' | 'failed' | 'started' | 'success',
  provider: string,
  context: AuthLogContext = {},
): void {
  if (event === 'failed' || event === 'email_unverified') {
    logAuthWarning(payload, `OAuth ${event}`, { provider, ...context })
  } else {
    logAuthSuccess(payload, `OAuth ${event}`, { provider, ...context })
  }
}

/**
 * Logs WebAuthn/Passkey events
 */
export function logWebAuthnEvent(
  payload: PayloadRequest['payload'],
  event:
    | 'authentication_failed'
    | 'authentication_started'
    | 'authentication_success'
    | 'registration_failed'
    | 'registration_started'
    | 'registration_success',
  userId?: string,
  credentialId?: string,
  context: AuthLogContext = {},
): void {
  const isFailure = event.includes('failed')

  if (isFailure) {
    logAuthError(payload, `WebAuthn ${event}`, new Error('WebAuthn operation failed'), {
      credentialId: credentialId ? createTokenPreview(credentialId) : undefined,
      userId,
      ...context,
    })
  } else {
    logAuthSuccess(payload, `WebAuthn ${event}`, {
      credentialId: credentialId ? createTokenPreview(credentialId) : undefined,
      userId,
      ...context,
    })
  }
}

/**
 * Logs magic link events
 */
export function logMagicLinkEvent(
  payload: PayloadRequest['payload'],
  event:
    | 'expired'
    | 'requested'
    | 'send_failed'
    | 'sent'
    | 'verification_failed'
    | 'verification_success',
  email: string,
  context: AuthLogContext = {},
): void {
  const isFailure = event.includes('failed') || event === 'expired'

  if (isFailure) {
    logAuthError(payload, `Magic link ${event}`, new Error('Magic link operation failed'), {
      email,
      ...context,
    })
  } else {
    logAuthSuccess(payload, `Magic link ${event}`, {
      email,
      ...context,
    })
  }
}

/**
 * Logs authentication attempt patterns (for anomaly detection)
 */
export function logAuthAttempt(
  payload: PayloadRequest['payload'],
  method: 'magic_link' | 'oauth' | 'refresh' | 'webauthn',
  result: 'failure' | 'success',
  context: { email?: string } & AuthLogContext,
): void {
  const logData = {
    method,
    result,
    timestamp: new Date().toISOString(),
    ...context,
  }

  if (result === 'failure') {
    logAuthWarning(payload, `Authentication attempt failed`, logData)
  } else {
    logAuthSuccess(payload, `Authentication attempt successful`, logData)
  }
}
