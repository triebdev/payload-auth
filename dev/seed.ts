import type { Payload } from 'payload'

export const devUser = {
  email: 'dev@payload-auth.local',
}

/**
 * Seeds a single dev user so the dev/test app can authenticate immediately
 * (passwordless — log in via magic link or agent-login).
 * Idempotent: skips creation when the user already exists.
 */
export const seed = async (payload: Payload): Promise<void> => {
  const existing = await payload.find({
    collection: 'users',
    limit: 1,
    where: { email: { equals: devUser.email } },
  })

  if (existing.docs.length > 0) {
    return
  }

  await payload.create({
    collection: 'users',
    data: {
      applicationContext: 'app',
      email: devUser.email,
      onboardingComplete: true,
    },
  })

  payload.logger.info(`[seed] Created dev user: ${devUser.email}`)
}
