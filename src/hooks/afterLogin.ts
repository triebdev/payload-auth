import type { CollectionAfterLoginHook } from 'payload'

import { getClientIp } from '../utilities/getClientIp'
import { asLoosePayload } from '../utilities/loosePayload'

/**
 * Tracks the last login timestamp and IP address on the user document.
 * Payload handles account locking natively via maxLoginAttempts/lockTime.
 * This hook only records metadata for audit purposes.
 */
export function createTrackLastLoginHook(usersSlug: string): CollectionAfterLoginHook {
  return async ({ req, user }) => {
    const { payload } = req
    const clientIp = getClientIp(req)

    try {
      await asLoosePayload(payload).update({
        id: user.id,
        collection: usersSlug,
        context: { skipHooks: true },
        data: {
          lastLoginAt: new Date().toISOString(),
          lastLoginIp: clientIp,
        },
      })

      payload.logger.info({ ip: clientIp, userId: user.id }, 'User logged in')
    } catch (error) {
      payload.logger.error({ err: error, userId: user.id }, 'Failed to update last login info')
    }

    return user
  }
}
