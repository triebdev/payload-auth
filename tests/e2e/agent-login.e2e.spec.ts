import { expect, test } from '@playwright/test'

/**
 * Smoke test for the full auth stack against a real Next.js server + Mongo
 * instance: session cookies are set by the dev-only agent-login endpoint,
 * and a subsequent authenticated request is accepted by the plugin's JWT
 * auth strategy. Exercises cookie handling and token verification without
 * needing a UI login form or a captured email.
 */
test('agent-login establishes a session that authenticates later requests', async ({
  context,
  page,
}) => {
  const response = await page.goto(
    '/api/auth/agent-login?secret=dev-agent-login-secret&returnUrl=/admin',
  )
  expect(response?.ok()).toBe(true)

  const cookies = await context.cookies()
  expect(cookies.find((c) => c.name === 'payload-token')).toBeTruthy()
  expect(cookies.find((c) => c.name === 'refresh-token')).toBeTruthy()

  const authedResponse = await page.request.post('/api/auth/webauthn/has-credentials')
  expect(authedResponse.status()).toBe(200)
})

test('agent-login is rejected with the wrong secret', async ({ page }) => {
  const response = await page.goto('/api/auth/agent-login?secret=wrong-secret')
  expect(response?.status()).toBe(403)
})
