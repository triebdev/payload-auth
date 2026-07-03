import type { CollectionConfig } from 'payload'

import { asCollectionSlug } from '../utilities/collectionSlug'

/**
 * Stores WebAuthn/Passkey credentials. Each document represents one registered
 * authenticator device for a user. Stored in a dedicated collection (instead of
 * a user sub-array) for query/uniqueness advantages and multi-device support.
 */
export function buildWebAuthnCredentialsCollection(args: {
  usersSlug: string
  webauthnSlug: string
}): CollectionConfig {
  const { usersSlug, webauthnSlug } = args

  return {
    slug: webauthnSlug,
    access: {
      create: ({ req: { user } }) => Boolean(user),
      delete: ({ req: { user } }) => {
        if (!user) {
          return false
        }
        return { user: { equals: user.id } }
      },
      read: ({ req: { user } }) => {
        if (!user) {
          return false
        }
        return { user: { equals: user.id } }
      },
      update: ({ req: { user } }) => {
        if (!user) {
          return false
        }
        return { user: { equals: user.id } }
      },
    },
    admin: {
      description: 'WebAuthn/Passkey credentials for passwordless authentication',
      hidden: true,
    },
    fields: [
      {
        name: 'user',
        type: 'relationship',
        index: true,
        relationTo: asCollectionSlug(usersSlug),
        required: true,
      },
      {
        name: 'credentialID',
        type: 'text',
        admin: { readOnly: true },
        index: true,
        required: true,
        unique: true,
      },
      {
        name: 'publicKey',
        type: 'textarea',
        admin: { readOnly: true },
        required: true,
      },
      {
        name: 'counter',
        type: 'number',
        admin: { readOnly: true },
        defaultValue: 0,
      },
      {
        name: 'transports',
        type: 'json',
        admin: {
          description: 'Authenticator transports (usb, ble, nfc, internal)',
          readOnly: true,
        },
      },
      {
        name: 'deviceName',
        type: 'text',
        admin: {
          description: 'User-assigned name for this device/passkey',
        },
      },
      {
        name: 'lastUsedAt',
        type: 'date',
        admin: { readOnly: true },
      },
    ],
    timestamps: true,
  }
}
