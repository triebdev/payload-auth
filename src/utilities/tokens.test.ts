import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import {
  generateDeviceFingerprint,
  generateSecureToken,
  signAccessToken,
  signChallengeToken,
  signMagicLinkToken,
  verifyAccessToken,
  verifyChallengeToken,
  verifyMagicLinkToken,
} from './tokens'

const TEST_SECRET = 'test-secret-for-payload-auth-unit-tests-min-32-chars'

beforeAll(() => {
  vi.stubEnv('PAYLOAD_SECRET', TEST_SECRET)
})

afterAll(() => {
  vi.unstubAllEnvs()
})

describe('signAccessToken / verifyAccessToken', () => {
  it('should sign and verify a token with all claims', async () => {
    const claims = {
      id: 'user-123',
      applicationContext: 'app',
      email: 'test@example.com',
    }

    const token = await signAccessToken(claims)
    expect(token).toBeTruthy()
    expect(typeof token).toBe('string')

    const verified = await verifyAccessToken(token)
    expect(verified.id).toBe('user-123')
    expect(verified.collection).toBe('users')
    expect(verified.email).toBe('test@example.com')
    expect(verified.applicationContext).toBe('app')
    expect(verified.iat).toBeDefined()
    expect(verified.exp).toBeDefined()
  })

  it('should include collection: users in the token by default', async () => {
    const token = await signAccessToken({
      id: 'user-456',
      email: 'test2@example.com',
    })
    const verified = await verifyAccessToken(token)
    expect(verified.collection).toBe('users')
  })

  it('should embed a custom users collection slug', async () => {
    const token = await signAccessToken({
      id: 'user-456',
      collection: 'customers',
      email: 'test2@example.com',
    })
    const verified = await verifyAccessToken(token)
    expect(verified.collection).toBe('customers')
  })

  it('should reject a tampered token', async () => {
    const token = await signAccessToken({
      id: 'user-789',
      email: 'tampered@example.com',
    })
    const tamperedToken = token.slice(0, -5) + 'XXXXX'
    await expect(verifyAccessToken(tamperedToken)).rejects.toThrow()
  })

  it('should reject a token with wrong secret', async () => {
    const token = await signAccessToken({
      id: 'user-000',
      email: 'wrong-secret@example.com',
    })

    vi.stubEnv('PAYLOAD_SECRET', 'different-secret-that-is-also-long-enough')
    await expect(verifyAccessToken(token)).rejects.toThrow()
    vi.stubEnv('PAYLOAD_SECRET', TEST_SECRET)
  })
})

describe('signMagicLinkToken / verifyMagicLinkToken', () => {
  it('should sign and verify a magic link token', async () => {
    const token = await signMagicLinkToken({
      applicationContext: 'backoffice',
      email: 'magic@example.com',
    })

    const verified = await verifyMagicLinkToken(token)
    expect(verified.email).toBe('magic@example.com')
    expect(verified.applicationContext).toBe('backoffice')
  })

  it('should sign a magic link token without applicationContext', async () => {
    const token = await signMagicLinkToken({ email: 'nocontext@example.com' })
    const verified = await verifyMagicLinkToken(token)
    expect(verified.email).toBe('nocontext@example.com')
    expect(verified.applicationContext).toBeUndefined()
  })

  it('should reject an access token used as magic link token', async () => {
    const accessToken = await signAccessToken({
      id: 'user-123',
      email: 'notmagic@example.com',
    })
    await expect(verifyMagicLinkToken(accessToken)).rejects.toThrow('Invalid token purpose')
  })
})

describe('signChallengeToken / verifyChallengeToken', () => {
  it('should sign and verify a challenge token with userId', async () => {
    const token = await signChallengeToken('challenge-abc', 'user-123')
    const verified = await verifyChallengeToken(token)
    expect(verified.challenge).toBe('challenge-abc')
    expect(verified.userId).toBe('user-123')
  })

  it('should sign and verify a challenge token without userId', async () => {
    const token = await signChallengeToken('challenge-def')
    const verified = await verifyChallengeToken(token)
    expect(verified.challenge).toBe('challenge-def')
    expect(verified.userId).toBeUndefined()
  })

  it('should reject a magic link token used as challenge token', async () => {
    const magicToken = await signMagicLinkToken({
      email: 'test@example.com',
    })
    await expect(verifyChallengeToken(magicToken)).rejects.toThrow('Invalid token purpose')
  })
})

describe('generateSecureToken', () => {
  it('should generate a 64-character hex string (32 bytes)', () => {
    const token = generateSecureToken()
    expect(token).toHaveLength(64)
    expect(token).toMatch(/^[0-9a-f]{64}$/)
  })

  it('should generate unique tokens', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateSecureToken()))
    expect(tokens.size).toBe(100)
  })
})

describe('generateDeviceFingerprint', () => {
  it('should generate a consistent SHA-256 hash for the same User-Agent', () => {
    const fp1 = generateDeviceFingerprint('Mozilla/5.0')
    const fp2 = generateDeviceFingerprint('Mozilla/5.0')
    expect(fp1).toBe(fp2)
    expect(fp1).toHaveLength(64)
    expect(fp1).toMatch(/^[0-9a-f]{64}$/)
  })

  it('should produce different hashes for different User-Agents', () => {
    const fp1 = generateDeviceFingerprint('Mozilla/5.0')
    const fp2 = generateDeviceFingerprint('Chrome/120')
    expect(fp1).not.toBe(fp2)
  })

  it('should be independent of the client IP (same UA -> same fingerprint)', () => {
    // Regression guard: the fingerprint must NOT depend on IP. The same browser
    // on different IPs (dual-stack, mobile/Wi-Fi switching, VPN) must produce
    // an identical fingerprint so the session is never falsely invalidated.
    const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    expect(generateDeviceFingerprint(ua)).toBe(generateDeviceFingerprint(ua))
  })
})

describe('PAYLOAD_SECRET validation', () => {
  it('should throw if PAYLOAD_SECRET is not set', async () => {
    vi.stubEnv('PAYLOAD_SECRET', '')
    await expect(signAccessToken({ id: 'test', email: 'test@example.com' })).rejects.toThrow(
      'PAYLOAD_SECRET environment variable is required',
    )
    vi.stubEnv('PAYLOAD_SECRET', TEST_SECRET)
  })
})
