/**
 * Input validation helpers for the auth endpoints.
 */

/**
 * Email validation regex - follows RFC 5322 simplified pattern
 */
const EMAIL_REGEX =
  /^[\w.!#$%&'*+/=?^`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i

/**
 * Token validation regex - expects JWT format
 */
const TOKEN_REGEX = /^[\w-]+\.[\w-]+\.[\w-]*$/

/**
 * Validates an email address
 */
export function validateEmail(email: unknown): null | string {
  if (typeof email !== 'string') {
    return 'Email must be a string'
  }

  if (!email.trim()) {
    return 'Email is required'
  }

  if (email.length > 254) {
    return 'Email is too long'
  }

  if (!EMAIL_REGEX.test(email)) {
    return 'Invalid email format'
  }

  return null
}

/**
 * Validates a token (JWT format)
 */
export function validateToken(token: unknown, tokenName: string = 'token'): null | string {
  if (typeof token !== 'string') {
    return `${tokenName} must be a string`
  }

  if (!token.trim()) {
    return `${tokenName} is required`
  }

  if (token.length > 4096) {
    return `${tokenName} is too long`
  }

  // Basic JWT format validation
  if (!TOKEN_REGEX.test(token)) {
    return `Invalid ${tokenName} format`
  }

  return null
}

/**
 * Validates an application context against the configured context names.
 * When no contexts are configured, any context value is rejected.
 */
export function validateApplicationContext(
  context: unknown,
  validContexts: string[],
): null | string {
  if (typeof context !== 'string') {
    return 'Application context must be a string'
  }

  if (!validContexts.includes(context)) {
    return `Invalid application context. Must be one of: ${validContexts.join(', ')}`
  }

  return null
}

/**
 * Validates request body structure
 */
export function validateRequestBody(body: unknown, requiredFields: string[]): null | string {
  if (!body || typeof body !== 'object') {
    return 'Request body must be a valid object'
  }

  for (const field of requiredFields) {
    if (!(field in body)) {
      return `Missing required field: ${field}`
    }
  }

  return null
}

/**
 * Sanitizes string input
 */
export function sanitizeString(value: unknown, maxLength: number = 1000): string {
  if (typeof value !== 'string') {
    return ''
  }

  return value
    .trim()
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .substring(0, maxLength)
}

/**
 * Validates and sanitizes name fields
 */
export function validateName(name: unknown, fieldName: string): { error?: string; value?: string } {
  if (typeof name !== 'string') {
    return { error: `${fieldName} must be a string` }
  }

  const trimmed = name.trim()

  if (!trimmed) {
    return { error: `${fieldName} is required` }
  }

  if (trimmed.length > 100) {
    return { error: `${fieldName} must be no more than 100 characters long` }
  }

  // Allow only letters (including accented Latin-1 names), spaces, hyphens,
  // and apostrophes. The À-ÿ range also matches ×/÷, which is harmless here.
  // eslint-disable-next-line regexp/no-obscure-range
  if (!/^[a-zA-ZÀ-ÿ\s\-']+$/.test(trimmed)) {
    return { error: `${fieldName} can only contain letters, spaces, hyphens, and apostrophes` }
  }

  return { value: sanitizeString(trimmed, 100) }
}

/**
 * Comprehensive validation for magic link requests
 */
export function validateMagicLinkRequest(
  body: unknown,
  validContexts: string[],
): {
  data?: { applicationContext?: string; email: string }
  error?: string
} {
  // Validate body structure
  const bodyError = validateRequestBody(body, ['email'])
  if (bodyError) {
    return { error: bodyError }
  }

  const data = body as { applicationContext?: unknown; email: unknown }

  // Validate email
  const emailError = validateEmail(data.email)
  if (emailError) {
    return { error: emailError }
  }

  // Validate application context (optional, only meaningful when contexts are configured)
  if (data.applicationContext) {
    const contextError = validateApplicationContext(data.applicationContext, validContexts)
    if (contextError) {
      return { error: contextError }
    }
  }

  return {
    data: {
      applicationContext:
        data.applicationContext ? sanitizeString(data.applicationContext) : undefined,
      email: sanitizeString(data.email).toLowerCase(),
    },
  }
}

/**
 * Comprehensive validation for onboarding requests
 */
export function validateOnboardingRequest(body: unknown): {
  data?: { firstName: string; lastName: string }
  error?: string
} {
  // Validate body structure
  const bodyError = validateRequestBody(body, ['firstName', 'lastName'])
  if (bodyError) {
    return { error: bodyError }
  }

  const data = body as { firstName: unknown; lastName: unknown }

  // Validate first name
  const firstNameResult = validateName(data.firstName, 'First name')
  if (firstNameResult.error) {
    return { error: firstNameResult.error }
  }

  // Validate last name
  const lastNameResult = validateName(data.lastName, 'Last name')
  if (lastNameResult.error) {
    return { error: lastNameResult.error }
  }

  return {
    data: {
      firstName: firstNameResult.value!,
      lastName: lastNameResult.value!,
    },
  }
}
