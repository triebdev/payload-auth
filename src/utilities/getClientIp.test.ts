import type { PayloadRequest } from 'payload'

import { describe, expect, it } from 'vitest'

import { getClientIp } from './getClientIp'

function mockRequest(headers: Record<string, string> = {}): PayloadRequest {
  const headersObj = new Headers(headers)
  return { headers: headersObj } as unknown as PayloadRequest
}

describe('getClientIp', () => {
  it('should extract IP from x-forwarded-for header', () => {
    const req = mockRequest({ 'x-forwarded-for': '203.0.113.50' })
    expect(getClientIp(req)).toBe('203.0.113.50')
  })

  it('should return first IP from comma-separated x-forwarded-for', () => {
    const req = mockRequest({ 'x-forwarded-for': '203.0.113.50, 70.41.3.18, 150.172.238.178' })
    expect(getClientIp(req)).toBe('203.0.113.50')
  })

  it('should trim whitespace from IP', () => {
    const req = mockRequest({ 'x-forwarded-for': '  10.0.0.1  ' })
    expect(getClientIp(req)).toBe('10.0.0.1')
  })

  it('should return undefined when no x-forwarded-for header', () => {
    const req = mockRequest({})
    expect(getClientIp(req)).toBeUndefined()
  })

  it('should return undefined for empty x-forwarded-for header', () => {
    const req = mockRequest({ 'x-forwarded-for': '' })
    expect(getClientIp(req)).toBeUndefined()
  })

  it('should handle IPv6 addresses', () => {
    const req = mockRequest({ 'x-forwarded-for': '2001:db8::1' })
    expect(getClientIp(req)).toBe('2001:db8::1')
  })
})
