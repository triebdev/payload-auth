import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from '@simplewebauthn/server'
import type { Endpoint, PayloadRequest } from 'payload'

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'

import type { ResolvedAuthPluginOptions } from '../types'

import { getClientIp } from '../utilities/getClientIp'
import { asLoosePayload, type LooseDoc } from '../utilities/loosePayload'
import { buildAuthCookieHeader, createSession } from '../utilities/session'
import { signChallengeToken, verifyChallengeToken } from '../utilities/tokens'
import { resolveWebAuthnRP } from '../utilities/webauthnRP'

/**
 * Returns true if the requesting user may view or manage credentials
 * for the given target user. Users can always manage their own credentials;
 * the `webauthn.canManageUser` option can extend this (e.g. for admin
 * support tooling).
 */
function canManageCredentialsForUser(
  options: ResolvedAuthPluginOptions,
  reqUser: PayloadRequest['user'],
  targetUserId: string,
): boolean {
  if (!reqUser) {
    return false
  }
  if (String(reqUser.id) === String(targetUserId)) {
    return true
  }
  if (options.webauthn.canManageUser) {
    return options.webauthn.canManageUser(
      reqUser as unknown as Record<string, unknown>,
      targetUserId,
    )
  }
  return false
}

/**
 * Creates the WebAuthn/Passkey endpoints:
 * - POST /api/auth/webauthn/register-options     — generate registration options
 * - POST /api/auth/webauthn/register-verify      — verify registration response
 * - POST /api/auth/webauthn/has-credentials      — check if user has registered credentials
 * - GET  /api/auth/webauthn/credentials          — list current user's credentials
 * - DELETE /api/auth/webauthn/credentials/:id    — delete a credential
 * - POST /api/auth/webauthn/authenticate-options — generate authentication options
 * - POST /api/auth/webauthn/authenticate-verify  — verify authentication response
 */
export function createWebAuthnEndpoints(
  options: ResolvedAuthPluginOptions,
  webauthnSlug: string,
): Endpoint[] {
  return [
    // === Registration Options ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        try {
          // Get existing credentials for this user
          const existing = await asLoosePayload(payload).find({
            collection: webauthnSlug,
            depth: 0,
            where: { user: { equals: user.id } },
          })

          const excludeCredentials = existing.docs.map((cred) => ({
            id: cred.credentialID as string,
            transports: (cred.transports as AuthenticatorTransportFuture[]) || [],
          }))

          const { rpID } = resolveWebAuthnRP(req, options)

          const registrationOptions = await generateRegistrationOptions({
            attestationType: 'none',
            authenticatorSelection: {
              residentKey: 'preferred',
              userVerification: 'preferred',
            },
            excludeCredentials,
            rpID,
            rpName: options.rpName,
            userDisplayName: String((user.name as string | undefined) || user.email),
            userName: String(user.email),
          })

          // Store challenge in a signed JWT (stateless)
          const challengeToken = await signChallengeToken(
            registrationOptions.challenge,
            String(user.id),
          )

          return Response.json({
            challengeToken,
            options: registrationOptions,
          })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn registration options failed')
          return Response.json({ error: 'Failed to generate options' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/webauthn/register-options',
    },

    // === Registration Verification ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        let body: {
          challengeToken?: string
          deviceName?: string
          response?: RegistrationResponseJSON
        }
        try {
          body = await req.json!()
        } catch {
          return Response.json({ error: 'Invalid request body' }, { status: 400 })
        }

        const { challengeToken, deviceName, response: attestation } = body

        if (!attestation || !challengeToken) {
          return Response.json(
            { error: 'Response and challengeToken are required' },
            { status: 400 },
          )
        }

        try {
          // Verify the challenge token
          const { challenge, userId } = await verifyChallengeToken(challengeToken)

          if (userId !== String(user.id)) {
            return Response.json({ error: 'Challenge user mismatch' }, { status: 403 })
          }

          const { origin, rpID } = resolveWebAuthnRP(req, options)

          const verification = await verifyRegistrationResponse({
            expectedChallenge: challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            response: attestation,
          })

          if (!verification.verified || !verification.registrationInfo) {
            return Response.json({ error: 'Verification failed' }, { status: 400 })
          }

          const { credential } = verification.registrationInfo

          // Store the credential
          await asLoosePayload(payload).create({
            collection: webauthnSlug,
            data: {
              counter: credential.counter,
              credentialID: credential.id,
              deviceName: deviceName || 'Unnamed Device',
              lastUsedAt: new Date().toISOString(),
              publicKey: Buffer.from(credential.publicKey).toString('base64url'),
              transports: attestation.response.transports || [],
              user: user.id,
            },
          })

          payload.logger.info(
            { credentialID: credential.id, userId: user.id },
            'WebAuthn credential registered',
          )

          return Response.json({ verified: true })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn registration verification failed')
          return Response.json({ error: 'Verification failed' }, { status: 400 })
        }
      },
      method: 'post',
      path: '/auth/webauthn/register-verify',
    },

    // === Has Credentials ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        try {
          const existing = await asLoosePayload(payload).find({
            collection: webauthnSlug,
            depth: 0,
            limit: 1,
            where: { user: { equals: user.id } },
          })

          return Response.json({ hasPasskey: existing.docs.length > 0 })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn has-credentials check failed')
          return Response.json({ error: 'Check failed' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/webauthn/has-credentials',
    },

    // === List Credentials ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        try {
          // Allow privileged users to list credentials for another user via ?userId=
          const url = new URL(req.url || '/', options.serverURL)
          const targetUserId = url.searchParams.get('userId') || String(user.id)

          if (!canManageCredentialsForUser(options, user, targetUserId)) {
            return Response.json({ error: 'Unauthorized' }, { status: 403 })
          }

          const result = await asLoosePayload(payload).find({
            collection: webauthnSlug,
            depth: 0,
            where: { user: { equals: targetUserId } },
          })

          const credentials = result.docs.map((doc) => ({
            id: doc.id,
            createdAt: doc.createdAt,
            deviceName: doc.deviceName,
            lastUsedAt: doc.lastUsedAt,
            transports: doc.transports,
          }))

          return Response.json({ credentials })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn credentials list failed')
          return Response.json({ error: 'Failed to list credentials' }, { status: 500 })
        }
      },
      method: 'get',
      path: '/auth/webauthn/credentials',
    },

    // === Delete Credential ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        const id = req.routeParams?.id
        if (!id) {
          return Response.json({ error: 'Credential ID is required' }, { status: 400 })
        }

        try {
          // Verify the credential belongs to the current user (or a privileged
          // user) before deleting
          const existing = await asLoosePayload(payload).findByID({
            id: id as string,
            collection: webauthnSlug,
            depth: 0,
          })

          if (!existing) {
            return Response.json({ error: 'Credential not found' }, { status: 404 })
          }

          if (!canManageCredentialsForUser(options, user, String(existing.user))) {
            return Response.json({ error: 'Unauthorized' }, { status: 403 })
          }

          await asLoosePayload(payload).delete({
            id: id as string,
            collection: webauthnSlug,
          })

          payload.logger.info({ credentialId: id, userId: user.id }, 'WebAuthn credential deleted')

          return Response.json({ deleted: true })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn credential delete failed')
          return Response.json({ error: 'Failed to delete credential' }, { status: 500 })
        }
      },
      method: 'delete',
      path: '/auth/webauthn/credentials/:id',
    },

    // === Authentication Options ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload } = req

        let body: { email?: string }
        try {
          body = await req.json!()
        } catch {
          body = {}
        }

        try {
          let allowCredentials:
            Array<{ id: string; transports?: AuthenticatorTransportFuture[] }> | undefined
          let userId: string | undefined

          // If email is provided, scope to that user's credentials
          if (body.email) {
            const userResult = await asLoosePayload(payload).find({
              collection: options.usersSlug,
              depth: 0,
              limit: 1,
              where: { email: { equals: body.email } },
            })

            const user = userResult.docs[0]
            if (user) {
              userId = String(user.id)
              const credentials = await asLoosePayload(payload).find({
                collection: webauthnSlug,
                depth: 0,
                where: { user: { equals: user.id } },
              })

              allowCredentials = credentials.docs.map((cred) => ({
                id: cred.credentialID as string,
                transports: (cred.transports as AuthenticatorTransportFuture[]) || [],
              }))
            }
          }

          const { rpID } = resolveWebAuthnRP(req, options)

          const authOptions = await generateAuthenticationOptions({
            allowCredentials,
            rpID,
            userVerification: 'preferred',
          })

          const challengeToken = await signChallengeToken(authOptions.challenge, userId)

          return Response.json({
            challengeToken,
            options: authOptions,
          })
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn authentication options failed')
          return Response.json({ error: 'Failed to generate options' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/webauthn/authenticate-options',
    },

    // === Authentication Verification ===
    {
      handler: async (req: PayloadRequest) => {
        const { payload } = req

        let body: {
          challengeToken?: string
          response?: AuthenticationResponseJSON
        }
        try {
          body = await req.json!()
        } catch {
          return Response.json({ error: 'Invalid request body' }, { status: 400 })
        }

        const { challengeToken, response: assertion } = body

        if (!assertion || !challengeToken) {
          return Response.json(
            { error: 'Response and challengeToken are required' },
            { status: 400 },
          )
        }

        try {
          // Verify the challenge token
          const { challenge } = await verifyChallengeToken(challengeToken)

          // Find the credential
          const credResult = await asLoosePayload(payload).find({
            collection: webauthnSlug,
            depth: 1,
            limit: 1,
            where: { credentialID: { equals: assertion.id } },
          })

          const credDoc = credResult.docs[0]
          if (!credDoc) {
            return Response.json({ error: 'Credential not found' }, { status: 404 })
          }

          const publicKeyBytes = Buffer.from(credDoc.publicKey as string, 'base64url')

          const { origin: authVerifyOrigin, rpID: authVerifyRpID } = resolveWebAuthnRP(req, options)

          const verification = await verifyAuthenticationResponse({
            credential: {
              id: credDoc.credentialID as string,
              counter: (credDoc.counter as number) || 0,
              publicKey: new Uint8Array(publicKeyBytes),
              transports: (credDoc.transports as AuthenticatorTransportFuture[]) || [],
            },
            expectedChallenge: challenge,
            expectedOrigin: authVerifyOrigin,
            expectedRPID: authVerifyRpID,
            response: assertion,
          })

          if (!verification.verified) {
            return Response.json({ error: 'Authentication failed' }, { status: 401 })
          }

          // Update credential counter and last used
          await asLoosePayload(payload).update({
            id: credDoc.id,
            collection: webauthnSlug,
            data: {
              counter: verification.authenticationInfo.newCounter,
              lastUsedAt: new Date().toISOString(),
            },
          })

          // Get the user (credDoc.user is populated at depth:1)
          const user = (
            typeof credDoc.user === 'object' && credDoc.user !== null ?
              credDoc.user
            : await asLoosePayload(payload).findByID({
                id: credDoc.user as string,
                collection: options.usersSlug,
              })) as LooseDoc

          // Create session and return tokens
          const session = await createSession({
            clientIp: getClientIp(req),
            payload,
            sessionsSlug: options.sessionsSlug,
            tokenConfig: options.tokens,
            user: {
              id: String(user.id),
              applicationContext: user.applicationContext as null | string | undefined,
              email: user.email as string,
            },
            userAgent: req.headers?.get?.('user-agent') || undefined,
            usersSlug: options.usersSlug,
          })

          // Update last login
          await asLoosePayload(payload).update({
            id: String(user.id),
            collection: options.usersSlug,
            context: { skipHooks: true },
            data: {
              lastLoginAt: new Date().toISOString(),
              lastLoginIp: getClientIp(req),
            },
          })

          const headers = new Headers({ 'Content-Type': 'application/json' })
          headers.append(
            'Set-Cookie',
            buildAuthCookieHeader(
              'payload-token',
              session.accessToken,
              options.tokens.accessTokenLifetime,
            ),
          )
          headers.append(
            'Set-Cookie',
            buildAuthCookieHeader(
              'refresh-token',
              session.refreshToken,
              Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
            ),
          )

          const needsOnboarding =
            options.enableOnboarding &&
            (!user.firstName || !user.lastName || !user.onboardingComplete)

          return new Response(
            JSON.stringify({
              needsOnboarding,
              user: { id: String(user.id), email: user.email },
              verified: true,
            }),
            { headers, status: 200 },
          )
        } catch (error) {
          payload.logger.error({ err: error }, 'WebAuthn authentication verification failed')
          return Response.json({ error: 'Authentication failed' }, { status: 401 })
        }
      },
      method: 'post',
      path: '/auth/webauthn/authenticate-verify',
    },
  ]
}
