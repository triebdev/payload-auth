import type { PayloadRequest } from 'payload'

/**
 * Extracts the client IP address from the request.
 * In production behind a reverse proxy, the IP comes from the x-forwarded-for header.
 * NextRequest does not expose `req.ip`, so we always use headers.
 */
export function getClientIp(req: PayloadRequest): string | undefined {
  const forwardedFor = req.headers?.get?.('x-forwarded-for') ?? ''
  return forwardedFor.split(',')[0]?.trim() || undefined
}
