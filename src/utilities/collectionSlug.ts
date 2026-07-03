import type { CollectionSlug } from 'payload'

/**
 * This plugin's collection slugs (`usersSlug`, `sessionsSlug`, `webauthnSlug`)
 * are runtime-configurable via plugin options, so they can't be typed against
 * Payload's per-consuming-app generated `CollectionSlug` union. Narrow a
 * configured slug string to that union at each call-site boundary instead of
 * loosening the surrounding Payload types.
 */
export function asCollectionSlug(slug: string): CollectionSlug {
  return slug as CollectionSlug
}
