'use client'

/**
 * Ships unstyled. Every element exposes a plain `className` hook (see the
 * `*ClassName` props and the default `payload-auth-*` class names below) so
 * the consuming app can style it with whatever CSS approach it already uses
 * (Tailwind, CSS Modules, plain CSS, etc.) — this package intentionally does
 * not bundle a stylesheet or depend on a UI library.
 */

import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/browser'

import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { useRouter, useSearchParams } from 'next/navigation'
import { useCallback, useEffect, useState } from 'react'

type LoginStep = 'add-passkey' | 'email' | 'magic-link-sent' | 'onboarding' | 'success'

export interface LoginFormCopy {
  addPasskeyDescription?: string
  addPasskeySkip?: string
  addPasskeySubmit?: string
  addPasskeySubmitting?: string
  addPasskeyTitle?: string
  backToEmail?: string
  emailLabel?: string
  emailPlaceholder?: string
  errorGeneric?: string
  errorOAuthFailed?: string
  firstNameLabel?: string
  firstNamePlaceholder?: string
  lastNameLabel?: string
  lastNamePlaceholder?: string
  loginFacebook?: string
  loginGoogle?: string
  loginPasskey?: string
  loginSubmit?: string
  loginSubmitting?: string
  loginSubtitle?: string
  loginTitle?: string
  magicLinkSentDescription?: string
  magicLinkSentTitle?: string
  newUserHint?: string
  onboardingSubmit?: string
  onboardingSubmitting?: string
  onboardingSubtitle?: string
  onboardingTitle?: string
  or?: string
  successDescription?: string
  successTitle?: string
}

const DEFAULT_COPY: Required<LoginFormCopy> = {
  addPasskeyDescription:
    'Add a passkey to sign in faster next time — your fingerprint or face is all you will need.',
  addPasskeySkip: 'Not now',
  addPasskeySubmit: 'Add passkey',
  addPasskeySubmitting: 'Setting up...',
  addPasskeyTitle: 'Sign in faster next time',
  backToEmail: 'Use a different email',
  emailLabel: 'Email address',
  emailPlaceholder: 'name@example.com',
  errorGeneric: 'Something went wrong.',
  errorOAuthFailed: 'Sign-in failed. Please try again.',
  firstNameLabel: 'First name',
  firstNamePlaceholder: 'Your first name',
  lastNameLabel: 'Last name',
  lastNamePlaceholder: 'Your last name',
  loginFacebook: 'Continue with Facebook',
  loginGoogle: 'Continue with Google',
  loginPasskey: 'Continue with a passkey',
  loginSubmit: 'Send login link',
  loginSubmitting: 'Sending...',
  loginSubtitle: 'No password needed — we will email you a secure login link.',
  loginTitle: 'Sign in',
  magicLinkSentDescription: 'We sent a login link to {email}. Check your inbox and click the link.',
  magicLinkSentTitle: 'Check your email',
  newUserHint: 'New here? Just enter your email — your account will be created automatically.',
  onboardingSubmit: 'Save and continue',
  onboardingSubmitting: 'Saving...',
  onboardingSubtitle: 'Please complete your profile to continue.',
  onboardingTitle: 'Welcome!',
  or: 'or',
  successDescription: 'Redirecting...',
  successTitle: 'Signed in successfully',
}

export interface LoginFormProps {
  /**
   * Application context to attach to this login (e.g. distinguishes
   * multiple frontends served by the same Payload instance). Only sent to
   * the server when set — must match one of the plugin's configured
   * `contexts` keys, otherwise the magic-link request is rejected.
   */
  applicationContext?: string
  /** Additional class name for the outer wrapper. */
  className?: string
  /** Overrides for any of the default English copy. */
  copy?: LoginFormCopy
  /** Show the "Continue with Facebook" button. @default false */
  enableFacebookOAuth?: boolean
  /** Show the "Continue with Google" button. @default false */
  enableGoogleOAuth?: boolean
  /**
   * Show the email magic-link form. @default true
   */
  enableMagicLink?: boolean
  /**
   * Client-side override to prevent the onboarding step from being shown,
   * even if the server response indicates `needsOnboarding`. Defaults to
   * `true` (onboarding may be shown, server-driven).
   */
  enableOnboarding?: boolean
  /**
   * Offer passkey sign-in / passkey enrollment. Only actually rendered when
   * the browser also supports conditional mediation. @default true
   */
  enablePasskey?: boolean
  /** Where to redirect after a successful login. @default '/' */
  returnUrl?: string
}

function SpinnerIcon({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 24 24"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle cx="12" cy="12" opacity="0.25" r="10" stroke="currentColor" strokeWidth="3" />
      <path
        d="M22 12a10 10 0 0 0-10-10"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="3"
      />
    </svg>
  )
}

function GoogleGlyph({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      viewBox="0 0 48 48"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"
        fill="#FFC107"
      />
      <path
        d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"
        fill="#FF3D00"
      />
      <path
        d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238C29.211 35.091 26.715 36 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"
        fill="#4CAF50"
      />
      <path
        d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002 6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"
        fill="#1976D2"
      />
    </svg>
  )
}

function FacebookGlyph({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      viewBox="0 0 24 24"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"
        fill="#1877F2"
      />
    </svg>
  )
}

/**
 * Passwordless login flow: email magic link, optional passkey (WebAuthn),
 * optional Google/Facebook OAuth, and a short onboarding step for new users.
 * Talks directly to this plugin's own REST endpoints
 * (`/api/auth/magic-link/*`, `/api/auth/webauthn/*`, `/api/auth/onboarding`,
 * `/api/auth/oauth/*`).
 */
export function LoginForm({
  applicationContext,
  className,
  copy: copyOverrides,
  enableFacebookOAuth = false,
  enableGoogleOAuth = false,
  enableMagicLink = true,
  enableOnboarding = true,
  enablePasskey = true,
  returnUrl = '/',
}: LoginFormProps) {
  const copy = { ...DEFAULT_COPY, ...copyOverrides }
  const searchParams = useSearchParams()
  const router = useRouter()
  const [step, setStep] = useState<LoginStep>('email')
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<null | string>(null)
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [hasPasskeySupport, setHasPasskeySupport] = useState(false)

  const checkAndShowPasskeyPrompt = useCallback(async () => {
    const supported =
      enablePasskey &&
      typeof window !== 'undefined' &&
      window.PublicKeyCredential !== undefined &&
      PublicKeyCredential.isConditionalMediationAvailable !== undefined

    if (!supported) {
      setStep('success')
      setTimeout(() => router.push(returnUrl), 1000)
      return
    }

    try {
      const res = await fetch('/api/auth/webauthn/has-credentials', {
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!res.ok) {
        setStep('success')
        setTimeout(() => router.push(returnUrl), 1000)
        return
      }

      const { hasPasskey } = await res.json()

      if (hasPasskey) {
        setStep('success')
        setTimeout(() => router.push(returnUrl), 1000)
      } else {
        setStep('add-passkey')
      }
    } catch {
      setStep('success')
      setTimeout(() => router.push(returnUrl), 1000)
    }
  }, [enablePasskey, returnUrl, router])

  const verifyMagicLink = useCallback(
    async (token: string, signal?: AbortSignal) => {
      setIsLoading(true)
      setError(null)

      try {
        const res = await fetch('/api/auth/magic-link/verify', {
          body: JSON.stringify({ token }),
          headers: { 'Content-Type': 'application/json' },
          method: 'POST',
          signal,
        })

        if (!res.ok) {
          const data = await res.json()
          throw new Error(data.error || copy.errorGeneric)
        }

        const data = await res.json()

        if (enableOnboarding && data.needsOnboarding) {
          setStep('onboarding')
        } else {
          await checkAndShowPasskeyPrompt()
        }
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          return
        }
        setError(err instanceof Error ? err.message : copy.errorGeneric)
        setStep('email')
      } finally {
        setIsLoading(false)
      }
    },
    [checkAndShowPasskeyPrompt, copy.errorGeneric, enableOnboarding],
  )

  // Check for magic link token in URL and handle onboarding step from OAuth redirect
  useEffect(() => {
    const token = searchParams.get('token')
    const stepParam = searchParams.get('step')
    const errorParam = searchParams.get('error')

    if (errorParam) {
      setError(errorParam === 'oauth_failed' ? copy.errorOAuthFailed : copy.errorGeneric)
    }

    if (token) {
      const controller = new AbortController()
      void verifyMagicLink(token, controller.signal)
      return () => controller.abort()
    }

    if (enableOnboarding && stepParam === 'onboarding') {
      setStep('onboarding')
    }

    // Check WebAuthn conditional-mediation support
    if (
      enablePasskey &&
      typeof window !== 'undefined' &&
      window.PublicKeyCredential &&
      PublicKeyCredential.isConditionalMediationAvailable
    ) {
      void PublicKeyCredential.isConditionalMediationAvailable().then((available) => {
        setHasPasskeySupport(available)
      })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, verifyMagicLink])

  async function requestMagicLink() {
    setIsLoading(true)
    setError(null)

    try {
      const body: { applicationContext?: string; email: string } = { email }
      if (applicationContext) {
        body.applicationContext = applicationContext
      }

      const res = await fetch('/api/auth/magic-link/request', {
        body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || copy.errorGeneric)
      }

      setStep('magic-link-sent')
    } catch (err) {
      setError(err instanceof Error ? err.message : copy.errorGeneric)
    } finally {
      setIsLoading(false)
    }
  }

  async function handlePasskeyLogin() {
    setIsLoading(true)
    setError(null)

    try {
      // Get authentication options from server
      const optionsRes = await fetch('/api/auth/webauthn/authenticate-options', {
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!optionsRes.ok) {
        throw new Error(copy.errorGeneric)
      }

      const { challengeToken, options } = await optionsRes.json()

      // Trigger browser passkey dialog
      const credential: AuthenticationResponseJSON = await startAuthentication({
        optionsJSON: options,
      })

      // Verify with server
      const verifyRes = await fetch('/api/auth/webauthn/authenticate-verify', {
        body: JSON.stringify({ challengeToken, response: credential }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!verifyRes.ok) {
        const data = await verifyRes.json()
        throw new Error(data.error || copy.errorGeneric)
      }

      const data = await verifyRes.json()

      if (enableOnboarding && data.needsOnboarding) {
        setStep('onboarding')
      } else {
        await checkAndShowPasskeyPrompt()
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'NotAllowedError') {
        setError(copy.errorGeneric)
      } else {
        setError(err instanceof Error ? err.message : copy.errorGeneric)
      }
    } finally {
      setIsLoading(false)
    }
  }

  async function handleRegisterPasskey() {
    setIsLoading(true)
    setError(null)

    try {
      const optionsRes = await fetch('/api/auth/webauthn/register-options', {
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!optionsRes.ok) {
        throw new Error(copy.errorGeneric)
      }

      const { challengeToken, options } = await optionsRes.json()

      const credential: RegistrationResponseJSON = await startRegistration({ optionsJSON: options })

      const verifyRes = await fetch('/api/auth/webauthn/register-verify', {
        body: JSON.stringify({ challengeToken, response: credential }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!verifyRes.ok) {
        const data = await verifyRes.json()
        throw new Error(data.error || copy.errorGeneric)
      }

      setStep('success')
      setTimeout(() => router.push(returnUrl), 1000)
    } catch (err) {
      setError(err instanceof Error ? err.message : copy.errorGeneric)
    } finally {
      setIsLoading(false)
    }
  }

  async function handleOnboarding() {
    setIsLoading(true)
    setError(null)

    try {
      const res = await fetch('/api/auth/onboarding', {
        body: JSON.stringify({ firstName, lastName }),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || copy.errorGeneric)
      }

      await checkAndShowPasskeyPrompt()
    } catch (err) {
      setError(err instanceof Error ? err.message : copy.errorGeneric)
    } finally {
      setIsLoading(false)
    }
  }

  function handleGoogleLogin() {
    const params = new URLSearchParams({
      context: applicationContext || '',
      returnUrl,
    })
    window.location.href = `/api/auth/oauth/google?${params}`
  }

  function handleFacebookLogin() {
    const params = new URLSearchParams({
      context: applicationContext || '',
      returnUrl,
    })
    window.location.href = `/api/auth/oauth/facebook?${params}`
  }

  const wrapperClassName = ['payload-auth-login-form', className].filter(Boolean).join(' ')

  if (step === 'success') {
    return (
      <div className={`${wrapperClassName} payload-auth-step-success`} data-testid="login-success">
        <h2 className="payload-auth-title">{copy.successTitle}</h2>
        <p className="payload-auth-subtitle">{copy.successDescription}</p>
      </div>
    )
  }

  if (step === 'add-passkey') {
    return (
      <div
        className={`${wrapperClassName} payload-auth-step-add-passkey`}
        data-testid="add-passkey-step"
      >
        <div className="payload-auth-header">
          <h2 className="payload-auth-title">{copy.addPasskeyTitle}</h2>
          <p className="payload-auth-subtitle">{copy.addPasskeyDescription}</p>
        </div>

        {error && (
          <div className="payload-auth-error" data-testid="add-passkey-error" role="alert">
            {error}
          </div>
        )}

        <div className="payload-auth-actions">
          <button
            className="payload-auth-button payload-auth-button-primary"
            data-testid="add-passkey-submit"
            disabled={isLoading}
            onClick={handleRegisterPasskey}
            type="button"
          >
            {isLoading ?
              <>
                <SpinnerIcon className="payload-auth-icon payload-auth-spin" />{' '}
                {copy.addPasskeySubmitting}
              </>
            : copy.addPasskeySubmit}
          </button>

          <button
            className="payload-auth-button payload-auth-button-ghost"
            data-testid="add-passkey-skip"
            disabled={isLoading}
            onClick={() => {
              setError(null)
              setStep('success')
              setTimeout(() => router.push(returnUrl), 600)
            }}
            type="button"
          >
            {copy.addPasskeySkip}
          </button>
        </div>
      </div>
    )
  }

  if (step === 'onboarding') {
    return (
      <div
        className={`${wrapperClassName} payload-auth-step-onboarding`}
        data-testid="onboarding-form"
      >
        <div className="payload-auth-header">
          <h2 className="payload-auth-title">{copy.onboardingTitle}</h2>
          <p className="payload-auth-subtitle">{copy.onboardingSubtitle}</p>
        </div>

        {error && (
          <div className="payload-auth-error" data-testid="onboarding-error" role="alert">
            {error}
          </div>
        )}

        <form
          className="payload-auth-form"
          onSubmit={(e) => {
            e.preventDefault()
            void handleOnboarding()
          }}
        >
          <div className="payload-auth-field">
            <label className="payload-auth-label" htmlFor="payload-auth-first-name">
              {copy.firstNameLabel}
            </label>
            <input
              className="payload-auth-input"
              data-testid="onboarding-first-name"
              disabled={isLoading}
              id="payload-auth-first-name"
              onChange={(e) => setFirstName(e.target.value)}
              placeholder={copy.firstNamePlaceholder}
              required
              type="text"
              value={firstName}
            />
          </div>
          <div className="payload-auth-field">
            <label className="payload-auth-label" htmlFor="payload-auth-last-name">
              {copy.lastNameLabel}
            </label>
            <input
              className="payload-auth-input"
              data-testid="onboarding-last-name"
              disabled={isLoading}
              id="payload-auth-last-name"
              onChange={(e) => setLastName(e.target.value)}
              placeholder={copy.lastNamePlaceholder}
              required
              type="text"
              value={lastName}
            />
          </div>
          <button
            className="payload-auth-button payload-auth-button-primary"
            data-testid="onboarding-submit"
            disabled={isLoading || !firstName.trim() || !lastName.trim()}
            type="submit"
          >
            {isLoading ?
              <>
                <SpinnerIcon className="payload-auth-icon payload-auth-spin" />{' '}
                {copy.onboardingSubmitting}
              </>
            : copy.onboardingSubmit}
          </button>
        </form>
      </div>
    )
  }

  if (step === 'magic-link-sent') {
    return (
      <div className={`${wrapperClassName} payload-auth-step-magic-link-sent`}>
        <div className="payload-auth-header" data-testid="magic-link-sent">
          <h2 className="payload-auth-title">{copy.magicLinkSentTitle}</h2>
          <p className="payload-auth-subtitle">
            {copy.magicLinkSentDescription.replace('{email}', email)}
          </p>
        </div>

        <button
          className="payload-auth-button payload-auth-button-ghost"
          data-testid="back-to-email"
          onClick={() => {
            setStep('email')
            setError(null)
          }}
          type="button"
        >
          {copy.backToEmail}
        </button>
      </div>
    )
  }

  // Default: email step
  return (
    <div className={`${wrapperClassName} payload-auth-step-email`} data-testid="login-form">
      <div className="payload-auth-header">
        <h2 className="payload-auth-title">{copy.loginTitle}</h2>
        <p className="payload-auth-subtitle">{copy.loginSubtitle}</p>
      </div>

      {error && (
        <div className="payload-auth-error" data-testid="login-error" role="alert">
          {error}
        </div>
      )}

      {enableMagicLink && (
        <form
          className="payload-auth-form"
          onSubmit={(e) => {
            e.preventDefault()
            void requestMagicLink()
          }}
        >
          <div className="payload-auth-field">
            <label className="payload-auth-label" htmlFor="payload-auth-login-email">
              {copy.emailLabel}
            </label>
            <input
              autoComplete="email webauthn"
              className="payload-auth-input"
              data-testid="login-email"
              disabled={isLoading}
              id="payload-auth-login-email"
              onChange={(e) => setEmail(e.target.value)}
              placeholder={copy.emailPlaceholder}
              required
              type="email"
              value={email}
            />
          </div>
          <button
            className="payload-auth-button payload-auth-button-primary"
            data-testid="login-submit"
            disabled={isLoading || !email.trim()}
            type="submit"
          >
            {isLoading ?
              <>
                <SpinnerIcon className="payload-auth-icon payload-auth-spin" />{' '}
                {copy.loginSubmitting}
              </>
            : copy.loginSubmit}
          </button>
        </form>
      )}

      {enableMagicLink && (enableGoogleOAuth || enableFacebookOAuth || enablePasskey) && (
        <div className="payload-auth-separator" role="separator">
          <span className="payload-auth-separator-line" />
          <span className="payload-auth-separator-label">{copy.or}</span>
          <span className="payload-auth-separator-line" />
        </div>
      )}

      {(enableGoogleOAuth || enableFacebookOAuth || enablePasskey) && (
        <div className="payload-auth-actions">
          {enableGoogleOAuth && (
            <button
              className="payload-auth-button payload-auth-button-outline"
              data-testid="login-google"
              disabled={isLoading}
              onClick={handleGoogleLogin}
              type="button"
            >
              <GoogleGlyph className="payload-auth-icon" />
              {copy.loginGoogle}
            </button>
          )}

          {enableFacebookOAuth && (
            <button
              className="payload-auth-button payload-auth-button-outline"
              data-testid="login-facebook"
              disabled={isLoading}
              onClick={handleFacebookLogin}
              type="button"
            >
              <FacebookGlyph className="payload-auth-icon" />
              {copy.loginFacebook}
            </button>
          )}

          {enablePasskey && hasPasskeySupport && (
            <button
              className="payload-auth-button payload-auth-button-outline"
              data-testid="login-passkey"
              disabled={isLoading}
              onClick={handlePasskeyLogin}
              type="button"
            >
              {copy.loginPasskey}
            </button>
          )}
        </div>
      )}

      {enableMagicLink && <p className="payload-auth-hint">{copy.newUserHint}</p>}
    </div>
  )
}
