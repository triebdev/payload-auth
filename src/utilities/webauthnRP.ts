import type { PayloadRequest } from 'payload'

import type { ResolvedAuthPluginOptions } from '../types'

import { getRequestOrigin } from './requestOrigin'

/**
 * Resolves the WebAuthn Relying Party ID (`rpID`) and expected origin for a
 * given request.
 *
 * WebAuthn requires `rpID` to be equal to (or a registrable-domain suffix of)
 * the origin the browser is actually on. A single static `rpID` breaks as soon
 * as the app is served from multiple hosts — e.g. `localhost` vs an
 * `app.localhost` subdomain used in local testing. Worse, browsers treat
 * `localhost` as an effective TLD/public suffix, so `localhost` is NOT a valid
 * rpID for an `app.localhost` origin, producing the "RP ID wrong"
 * SecurityError.
 *
 * We therefore derive the rpID/origin from the request host, but only honour it
 * when the origin is in the configured allowlist (`allowedOrigins` + the static
 * `serverURL`). This prevents a forged `Host`/`x-forwarded-host` header from
 * tricking the server into issuing credentials bound to an attacker domain.
 * Any non-allowlisted origin falls back to the static `serverURL`.
 */
export function resolveWebAuthnRP(
  req: PayloadRequest,
  options: Pick<ResolvedAuthPluginOptions, 'allowedOrigins' | 'rpID' | 'serverURL'>,
): { origin: string; rpID: string } {
  const requestOrigin = getRequestOrigin(req, options.serverURL)

  const allowed = new Set(
    [...(options.allowedOrigins || []), options.serverURL].filter(
      (o): o is string => typeof o === 'string' && o.length > 0,
    ),
  )

  const origin = allowed.has(requestOrigin) ? requestOrigin : options.serverURL

  let rpID: string
  try {
    rpID = new URL(origin).hostname
  } catch {
    // Defensive fallback: never throw out of the auth flow.
    rpID = options.rpID
  }

  return { origin, rpID }
}
