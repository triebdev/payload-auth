import type { Endpoint, PayloadRequest } from 'payload'

import type { ResolvedAuthPluginOptions } from '../types'

import { asLoosePayload } from '../utilities/loosePayload'
import { validateOnboardingRequest } from '../utilities/validation'

/**
 * Creates the onboarding endpoint:
 * - POST /api/auth/onboarding — updates user profile with required fields (firstName, lastName)
 */
export function createOnboardingEndpoints(options: ResolvedAuthPluginOptions): Endpoint[] {
  return [
    {
      handler: async (req: PayloadRequest) => {
        const { payload, user } = req

        if (!user) {
          return Response.json({ error: 'Authentication required' }, { status: 401 })
        }

        let body: unknown
        try {
          body = await req.json!()
        } catch {
          return Response.json({ error: 'Invalid request body' }, { status: 400 })
        }

        const validation = validateOnboardingRequest(body)
        if (validation.error) {
          return Response.json({ error: validation.error }, { status: 400 })
        }

        const { firstName, lastName } = validation.data!

        try {
          await asLoosePayload(payload).update({
            id: String(user.id),
            collection: options.usersSlug,
            data: {
              firstName,
              lastName,
              onboardingComplete: true,
            },
          })

          return Response.json({ success: true })
        } catch (error) {
          payload.logger.error({ err: error }, 'Onboarding update failed')
          return Response.json({ error: 'Failed to update profile' }, { status: 500 })
        }
      },
      method: 'post',
      path: '/auth/onboarding',
    },
  ]
}
