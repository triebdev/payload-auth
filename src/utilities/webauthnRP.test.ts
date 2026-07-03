import type { PayloadRequest } from 'payload'

import { describe, expect, it } from 'vitest'

import type { ResolvedAuthPluginOptions } from '../types'

import { resolveOptions } from '../types'
import { resolveWebAuthnRP } from './webauthnRP'

function makeOptions(
  overrides: Parameters<typeof resolveOptions>[0] = {},
): ResolvedAuthPluginOptions {
  return resolveOptions({
    allowedOrigins: ['http://app.localhost:3006', 'http://backoffice.localhost:3006'],
    rpID: 'localhost',
    rpName: 'Test App',
    serverURL: 'http://localhost:3006',
    ...overrides,
  })
}

function makeReq(headers: Record<string, string>, url = 'http://localhost:3006/'): PayloadRequest {
  return {
    headers: new Headers(headers),
    url,
  } as unknown as PayloadRequest
}

describe('resolveWebAuthnRP', () => {
  it('uses the allowlisted app.localhost subdomain when the browser is on it', () => {
    // Regression: rpID must be the actual host, not the static `localhost`,
    // otherwise WebAuthn throws "RP ID wrong" on the subdomain.
    const req = makeReq({ host: 'app.localhost:3006' })
    const { origin, rpID } = resolveWebAuthnRP(req, makeOptions())
    expect(rpID).toBe('app.localhost')
    expect(origin).toBe('http://app.localhost:3006')
  })

  it('uses localhost when the browser is on the bare serverURL host', () => {
    const req = makeReq({ host: 'localhost:3006' })
    const { origin, rpID } = resolveWebAuthnRP(req, makeOptions())
    expect(rpID).toBe('localhost')
    expect(origin).toBe('http://localhost:3006')
  })

  it('respects x-forwarded-host / x-forwarded-proto from a reverse proxy', () => {
    const req = makeReq({
      host: 'localhost:3006',
      'x-forwarded-host': 'app.localhost:3006',
      'x-forwarded-proto': 'http',
    })
    const { origin, rpID } = resolveWebAuthnRP(req, makeOptions())
    expect(rpID).toBe('app.localhost')
    expect(origin).toBe('http://app.localhost:3006')
  })

  it('honours a production subdomain in the allowlist (https)', () => {
    const options = makeOptions({
      allowedOrigins: ['https://app.example.com'],
      serverURL: 'https://example.com',
    })
    const req = makeReq(
      { host: 'app.example.com', 'x-forwarded-proto': 'https' },
      'https://app.example.com/',
    )
    const { origin, rpID } = resolveWebAuthnRP(req, options)
    expect(rpID).toBe('app.example.com')
    expect(origin).toBe('https://app.example.com')
  })

  it('falls back to serverURL when the request origin is NOT allowlisted (anti-spoofing)', () => {
    // A forged Host header must NOT be able to bind credentials to an attacker domain.
    const req = makeReq({ host: 'evil.example.com' }, 'http://evil.example.com/')
    const { origin, rpID } = resolveWebAuthnRP(req, makeOptions())
    expect(origin).toBe('http://localhost:3006')
    expect(rpID).toBe('localhost')
  })

  it('produces a matching rpID/origin pair so registration and verification agree', () => {
    const req = makeReq({ host: 'app.localhost:3006' })
    const { origin, rpID } = resolveWebAuthnRP(req, makeOptions())
    expect(new URL(origin).hostname).toBe(rpID)
  })
})
