import { useCallback, useEffect, useState } from 'react'
import HCaptcha from '@hcaptcha/react-hcaptcha'
import { LockKeyhole, ShieldCheck, UserRound } from 'lucide-react'
import { api } from '../services/api.js'
import { beginLogin, completeLogin } from '../services/authService.js'
import '../styles/login.css'

function getLoginError(error, otpRequired) {
  const status = error.response?.status

  if (status === 400) return 'The verification code is invalid or expired.'

  if (status === 401) {
    return otpRequired
      ? 'The verification code is invalid or expired.'
      : 'Invalid username or password.'
  }

  if (status === 403) return 'A valid CAPTCHA challenge is required.'
  if (status === 429) return 'Too many login attempts. Please wait and try again.'
  if (status === 503) return 'The verification service is unavailable. Please try again later.'
  if (status >= 500) return 'The server is unavailable. Please try again later.'

  return 'Unable to sign in. Please check your connection and try again.'
}

export default function Login({ onLogin, sessionExpired = false }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const [otpRequired, setOtpRequired] = useState(false)

  const [captcha, setCaptcha] = useState({
    required: false,
    siteKey: '',
  })

  const [captchaConfigError, setCaptchaConfigError] = useState(false)
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaWidgetKey, setCaptchaWidgetKey] = useState(0)

  const loadCaptchaConfig = useCallback(async () => {
    try {
      const response = await api.get('/captcha/config')

      setCaptcha(response.data)
      setCaptchaConfigError(false)
    } catch {
      setCaptcha({ required: true, siteKey: '' })
      setCaptchaConfigError(true)
    }
  }, [])

  useEffect(() => {
    let active = true

    api.get('/captcha/config')
      .then((response) => {
        if (active) {
          setCaptcha(response.data)
          setCaptchaConfigError(false)
        }
      })
      .catch(() => {
        if (active) {
          setCaptcha({ required: true, siteKey: '' })
          setCaptchaConfigError(true)
        }
      })

    return () => {
      active = false
    }
  }, [])

  async function handleSubmit(event) {
    event.preventDefault()

    setError('')
    setNotice('')
    setLoading(true)

    try {
      if (otpRequired) {
        const session = await completeLogin(
          username.trim(),
          password,
          otp
        )

        onLogin(session)
      } else {
        await beginLogin(
          username.trim(),
          password,
          captchaToken
        )

        setOtpRequired(true)
        setNotice(
          'A verification code has been sent to your configured email address.'
        )

        setCaptchaToken('')
        setCaptcha((current) => ({
          ...current,
          required: false,
        }))
      }
    } catch (requestError) {
      const status = requestError.response?.status

      if ([401, 403].includes(status)) {
        await loadCaptchaConfig()
      }

      if (captchaToken) {
        setCaptchaToken('')
        setCaptchaWidgetKey((current) => current + 1)
      }

      setError(getLoginError(requestError, otpRequired))
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="login-page">
      <section
        className="login-brand"
        aria-label="Login Activity Monitor"
      >
        <div className="brand-mark">
          <ShieldCheck size={34} />
        </div>

        <div>
          <p>Security monitoring</p>
          <h1>Login Activity Monitor</h1>
        </div>
      </section>

      <section
        className="login-card"
        aria-labelledby="login-heading"
      >
        <div className="login-heading">
          <h2 id="login-heading">
            {otpRequired ? 'Verify your sign-in' : 'Welcome back'}
          </h2>

          <p>
            {otpRequired
              ? 'Enter the one-time code sent to your configured email address.'
              : 'Sign in with your account credentials.'}
          </p>
        </div>

        {notice && (
          <div className="login-error" role="status">
            {notice}
          </div>
        )}

        {error && (
          <div className="login-error" role="alert">
            {error}
          </div>
        )}

        {!error && sessionExpired && (
          <div className="login-error" role="status">
            Your session expired. Please sign in again.
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Username</label>

          <div className="input-wrap">
            <UserRound size={18} aria-hidden="true" />

            <input
              id="username"
              name="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
              disabled={loading || otpRequired}
            />
          </div>

          {!otpRequired && (
            <>
              <label htmlFor="password">Password</label>

              <div className="input-wrap">
                <LockKeyhole size={18} aria-hidden="true" />

                <input
                  id="password"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  required
                  disabled={loading}
                />
              </div>

              {captcha.required && captcha.siteKey && (
                <div className="captcha-widget">
                  <HCaptcha
                    key={captchaWidgetKey}
                    sitekey={captcha.siteKey}
                    onVerify={(token) => {
                      setCaptchaToken(token)
                      setError('')
                    }}
                    onExpire={() => {
                      setCaptchaToken('')
                    }}
                    onError={() => {
                      setCaptchaToken('')
                      setError(
                        'The CAPTCHA challenge could not be loaded.'
                      )
                    }}
                  />
                </div>
              )}

              {captcha.required && !captcha.siteKey && (
                <p className="login-error" role="alert">
                  {captchaConfigError
                    ? 'CAPTCHA configuration could not be loaded.'
                    : 'CAPTCHA is required, but the site key is not configured.'}
                </p>
              )}
            </>
          )}

          {otpRequired && (
            <>
              <label htmlFor="otp">One-time password</label>

              <div className="input-wrap">
                <LockKeyhole size={18} aria-hidden="true" />

                <input
                  id="otp"
                  name="otp"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={otp}
                  onChange={(event) => setOtp(event.target.value)}
                  required
                  disabled={loading}
                />
              </div>
            </>
          )}

          <button
            type="submit"
            className="login-button"
            disabled={
              loading ||
              (!otpRequired && captcha.required && !captchaToken)
            }
          >
            {loading
              ? 'Signing in...'
              : otpRequired
                ? 'Verify code'
                : 'Sign in'}
          </button>
        </form>
      </section>
    </main>
  )
}