import type { MagicLinkEmailConfig, ResolvedAuthPluginOptions } from '../types'

/**
 * Resolves the effective email configuration for a request: per-context
 * config takes precedence over the global `email` config.
 */
export function resolveEmailConfig(
  options: ResolvedAuthPluginOptions,
  context?: string,
): MagicLinkEmailConfig {
  const contextEmail = context ? options.contexts[context]?.email : undefined
  return {
    buildEmailHTML: contextEmail?.buildEmailHTML ?? options.email.buildEmailHTML,
    from: contextEmail?.from ?? options.email.from,
    subject: contextEmail?.subject ?? options.email.subject,
  }
}

/**
 * Resolves the `from` address for a magic link email.
 * Falls back to the EMAIL_FROM_ADDRESS env var, then a generic default.
 */
export function resolveEmailFrom(config: MagicLinkEmailConfig): string {
  return config.from || process.env.EMAIL_FROM_ADDRESS || 'noreply@localhost'
}

/**
 * Resolves the subject for a magic link email.
 */
export function resolveEmailSubject(config: MagicLinkEmailConfig, context?: string): string {
  if (typeof config.subject === 'function') {
    return config.subject({ context })
  }
  return config.subject || 'Your login link'
}

/**
 * Builds the HTML email body for a magic link.
 * Uses the configured `buildEmailHTML` callback when provided, otherwise a
 * neutral default template.
 */
export async function buildMagicLinkEmail(
  config: MagicLinkEmailConfig,
  args: { context?: string; email: string; url: string },
): Promise<string> {
  if (config.buildEmailHTML) {
    return config.buildEmailHTML(args)
  }
  return buildDefaultMagicLinkEmail(args.url)
}

/**
 * Neutral, brand-free default magic link email template.
 */
export function buildDefaultMagicLinkEmail(magicLinkUrl: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f5;">
    <tr><td align="center" style="padding:40px 20px;">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08);">
        <!-- Header -->
        <tr><td style="background-color:#18181b;padding:32px 40px;text-align:center;">
          <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;">Sign in</h1>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:40px;">
          <h2 style="margin:0 0 8px;color:#18181b;font-size:20px;font-weight:600;">Your login link</h2>
          <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
            Click the button below to sign in. The link is valid for a limited time.
          </p>
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto 24px;">
            <tr><td style="background-color:#18181b;border-radius:8px;">
              <a href="${magicLinkUrl}" style="display:inline-block;padding:14px 36px;color:#ffffff;font-size:15px;font-weight:600;text-decoration:none;">
                Sign in &rarr;
              </a>
            </td></tr>
          </table>
          <p style="margin:0;color:#999;font-size:13px;line-height:1.5;">
            If you did not request this login, you can safely ignore this email.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`
}
