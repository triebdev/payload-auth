import type { PayloadRequest } from 'payload'

// Simple in-memory rate limiting store
const rateLimitStore = new Map<string, { count: number; resetTime: number }>()

interface RateLimitOptions {
  identifier?: string // Custom identifier (defaults to IP)
  maxRequests: number // Maximum requests per window
  windowMs: number // Time window in milliseconds
}

/**
 * Rate limiting middleware for Payload endpoints.
 * Uses in-memory storage for simplicity - consider Redis for production.
 */
export function createRateLimit(options: RateLimitOptions) {
  const { identifier, maxRequests, windowMs } = options

  // Kept async so a future backing store (e.g. Redis) can be swapped in
  // without changing the call sites, which already await this function.
  // eslint-disable-next-line @typescript-eslint/require-await
  return async (req: PayloadRequest): Promise<{ resetTime?: number; success: boolean }> => {
    // Get client identifier (IP address by default)
    const clientId = identifier || getClientIdentifier(req)

    if (!clientId) {
      return { success: true } // No rate limiting if we can't identify client
    }

    const now = Date.now()
    const key = `${clientId}:${req.routeParams?.path || req.url || 'unknown'}`

    // Clean up expired entries
    if (rateLimitStore.size > 10000) {
      // Prevent memory leaks
      for (const [storeKey, data] of rateLimitStore.entries()) {
        if (now > data.resetTime) {
          rateLimitStore.delete(storeKey)
        }
      }
    }

    const existing = rateLimitStore.get(key)

    if (!existing || now > existing.resetTime) {
      // First request or window expired
      rateLimitStore.set(key, {
        count: 1,
        resetTime: now + windowMs,
      })
      return { resetTime: now + windowMs, success: true }
    }

    if (existing.count >= maxRequests) {
      return { resetTime: existing.resetTime, success: false }
    }

    // Increment counter
    existing.count++
    return { resetTime: existing.resetTime, success: true }
  }
}

/**
 * Extracts client identifier from request for rate limiting.
 */
function getClientIdentifier(req: PayloadRequest): null | string {
  // Try various headers for client IP
  const forwardedFor = req.headers?.get('x-forwarded-for')
  const realIp = req.headers?.get('x-real-ip')
  const cfConnectingIp = req.headers?.get('cf-connecting-ip') // Cloudflare

  let ip: null | string = null

  if (forwardedFor) {
    // X-Forwarded-For can contain multiple IPs, take the first one
    ip = forwardedFor.split(',')[0].trim()
  } else if (realIp) {
    ip = realIp.trim()
  } else if (cfConnectingIp) {
    ip = cfConnectingIp.trim()
  }

  // Fallback to a hash of user agent if no IP available
  if (!ip) {
    const userAgent = req.headers?.get('user-agent') || 'unknown'
    return `ua:${Buffer.from(userAgent).toString('base64').substring(0, 16)}`
  }

  return `ip:${ip}`
}

// Pre-configured rate limiters for different endpoint types
export const authRateLimit = createRateLimit({
  maxRequests: 10, // 10 attempts per 15 minutes
  windowMs: 15 * 60 * 1000, // 15 minutes
})

export const magicLinkRateLimit = createRateLimit({
  maxRequests: 5, // 5 magic links per 15 minutes
  windowMs: 15 * 60 * 1000, // 15 minutes
})

export const refreshRateLimit = createRateLimit({
  maxRequests: 30, // 30 refresh attempts per minute
  windowMs: 60 * 1000, // 1 minute
})

export const onboardingRateLimit = createRateLimit({
  maxRequests: 3, // 3 onboarding attempts per hour
  windowMs: 60 * 60 * 1000, // 1 hour
})
