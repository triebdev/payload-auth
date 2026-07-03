import type { Payload, Where } from 'payload'

/**
 * This plugin's users/sessions/webauthn-credentials collection slugs are
 * runtime-configurable (plugin options), and the documents they return carry
 * fields this plugin itself defines at runtime (see `fields/userFields.ts`,
 * `collections/Sessions.ts`, `collections/WebAuthnCredentials.ts`). Both are
 * incompatible with Payload's per-consuming-app generated `CollectionSlug`/
 * `DataFromCollectionSlug` types, which assume a collection shape fixed at
 * compile time in the *consuming app*, not the plugin.
 *
 * `asLoosePayload` casts through this loosely typed view of Payload's CRUD
 * API at the plugin's DB boundary. Field access on the returned documents is
 * intentionally unchecked below this point — correctness relies on the
 * actual Payload schema the plugin defines, not on TypeScript.
 */
export interface LooseDoc {
  [key: string]: unknown
  id: number | string
}

export interface LoosePayload {
  count: (args: { collection: string; where?: Where }) => Promise<{ totalDocs: number }>
  create: (args: {
    collection: string
    context?: Record<string, unknown>
    data: Record<string, unknown>
  }) => Promise<LooseDoc>
  delete: (args: {
    collection: string
    id?: number | string
    where?: Where
  }) => Promise<{ docs?: LooseDoc[] } & Partial<LooseDoc>>
  find: (args: {
    collection: string
    depth?: number
    limit?: number
    where?: Where
  }) => Promise<{ docs: LooseDoc[] }>
  findByID: (args: { collection: string; depth?: number; id: number | string }) => Promise<LooseDoc>
  logger: Payload['logger']
  sendEmail: Payload['sendEmail']
  update: (args: {
    collection: string
    context?: Record<string, unknown>
    data: Record<string, unknown>
    id?: number | string
    where?: Where
  }) => Promise<LooseDoc>
}

export function asLoosePayload(payload: Payload): LoosePayload {
  return payload as unknown as LoosePayload
}
