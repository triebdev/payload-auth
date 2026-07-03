import type { PayloadRequest } from 'payload'

/**
 * Standardized error response format for all auth endpoints.
 * Ensures consistent error handling and prevents information leakage.
 */
export interface ErrorResponse {
  code?: string
  details?: Record<string, unknown>
  error: string
}

/**
 * Creates a standardized error response.
 */
export function createErrorResponse(
  error: string,
  status: number = 400,
  code?: string,
  details?: Record<string, unknown>,
): Response {
  const errorBody: ErrorResponse = { error }

  if (code) {
    errorBody.code = code
  }

  if (details && process.env.NODE_ENV === 'development') {
    errorBody.details = details
  }

  return Response.json(errorBody, { status })
}

/**
 * Common error responses for auth endpoints.
 */
export const AuthErrors = {
  invalidRequest: (details?: string) =>
    createErrorResponse(
      'Invalid request',
      400,
      'INVALID_REQUEST',
      details ? { message: details } : undefined,
    ),

  unauthorized: (message: string = 'Unauthorized') =>
    createErrorResponse(message, 401, 'UNAUTHORIZED'),

  forbidden: (message: string = 'Forbidden') => createErrorResponse(message, 403, 'FORBIDDEN'),

  notFound: (resource: string = 'Resource') =>
    createErrorResponse(`${resource} not found`, 404, 'NOT_FOUND'),

  rateLimited: (resetTime?: number) =>
    createErrorResponse('Too many requests', 429, 'RATE_LIMITED', { resetTime }),

  emailUnverified: () =>
    createErrorResponse('Email address must be verified', 403, 'EMAIL_UNVERIFIED'),

  invalidToken: (type: string = 'token') =>
    createErrorResponse(`Invalid or expired ${type}`, 401, 'INVALID_TOKEN'),

  sessionExpired: () => createErrorResponse('Session has expired', 401, 'SESSION_EXPIRED'),

  deviceMismatch: () =>
    createErrorResponse('Invalid session - device mismatch', 401, 'DEVICE_MISMATCH'),

  oauthFailed: (provider?: string) =>
    createErrorResponse(
      `OAuth authentication failed${provider ? ` with ${provider}` : ''}`,
      401,
      'OAUTH_FAILED',
    ),

  serverError: (details?: string) =>
    createErrorResponse(
      'Internal server error',
      500,
      'SERVER_ERROR',
      details ? { message: details } : undefined,
    ),

  emailRequired: () => createErrorResponse('Email is required', 400, 'EMAIL_REQUIRED'),

  tokenRequired: (type: string = 'token') =>
    createErrorResponse(`${type} is required`, 400, 'TOKEN_REQUIRED'),
}

/**
 * Logs error with consistent format and returns appropriate response.
 */
export function handleError(
  error: unknown,
  payload: PayloadRequest['payload'],
  context: string,
  defaultMessage: string = 'An error occurred',
): Response {
  const errorDetails = error instanceof Error ? error.message : String(error)

  payload.logger.error(
    {
      context,
      err: error instanceof Error ? error : new Error(errorDetails),
    },
    `${context}: ${errorDetails}`,
  )

  // Don't expose internal errors to clients
  if (error instanceof Error && error.name === 'PayloadError') {
    return AuthErrors.serverError()
  }

  return AuthErrors.serverError(defaultMessage)
}
