# Login Activity Monitor Frontend

React and Vite frontend for the existing Spring Boot Login Activity Monitor API.

## Requirements

- Node.js
- The Spring Boot backend running on port `8080` for local development
- MySQL configured for the backend

## Local development

```bash
cd frontend
npm install
npm run dev
```

The Vite server proxies `/api` requests to the Spring Boot backend at:

```text
http://localhost:8080
```

The proxy avoids CORS configuration for local browser development.

## Environment configuration

Copy `.env.example` to `.env.local` and set the backend API base as needed:

```bash
cp .env.example .env.local
```

For a production frontend and backend served under the same origin, use:

```text
VITE_API_BASE_URL=/api
```

For separate frontend and backend origins, set the complete backend API base URL:

```text
VITE_API_BASE_URL=https://backend.example.com/api
```

Do not put credentials, passwords, database secrets, or session secrets in frontend environment files.

## Production build

```bash
cd frontend
npm run build
```

Deploy the generated `frontend/dist` directory with a static host or reverse proxy.

For separate origins, the Spring Boot deployment must permit the frontend origin through Spring CORS configuration. For same-origin deployment, use a reverse proxy that forwards `/api` to Spring Boot and serves `dist` for frontend routes.

## Authentication behavior

- Public `POST /login` requires `username`, `ip_address`, and `status`, and accepts only `FAILURE`. The supplied IP is validated but is not trusted: rate limiting and stored records use the server-derived client IP. Authenticated `SUCCESS` records are created only after password and OTP verification. This intentionally differs from the PDF's client-supplied-IP request contract.
- Login first uses `POST /api/auth/login` with HTTP Basic authentication. A successful password check sends a short-lived OTP to the email address configured for that username.
- `POST /api/auth/otp/verify` requires the same Basic credentials and the OTP. A session is created only after OTP verification succeeds.
- Login stores only session metadata in browser session storage; the password and OTP are never stored there.
- After five failed attempts from an IP address within ten minutes, the login form displays hCaptcha. The backend verifies the hCaptcha response before accepting the login request.
- `GET /api/captcha/config` supplies the per-IP challenge status and public hCaptcha site key.
- Protected requests include `X-Session-Id`.
- HTTP 401 on a request with an active session clears it and returns the user to login.
- HTTP 403 displays an authorization message.
- HTTP 429 displays a rate-limit message.

## Backend authentication and email configuration

Configure these values in the backend process environment; do not put secrets in frontend files:

- `HCAPTCHA_SITE_KEY` and `HCAPTCHA_SECRET` from hCaptcha.
- `HCAPTCHA_REQUIRED` optionally forces CAPTCHA for every login when `true`; when `false`, the existing five-failures-in-ten-minutes threshold applies.
- `APP_NOTIFICATION_ADMIN_EMAIL` for administrator alerts.
- `APP_NOTIFICATION_USER_EMAILS` as comma-separated `username=email` mappings for OTP delivery and user alerts.
- `SPRING_MAIL_HOST`, `SPRING_MAIL_PORT`, `SPRING_MAIL_USERNAME`, and `SPRING_MAIL_PASSWORD` for SMTP. The SMTP username and password must be supplied externally.
- `APP_NOTIFICATION_FROM` optionally overrides the sender address.
- `APP_AUTH_OTP_VALIDITY_SECONDS` optionally changes OTP validity; it defaults to 90 seconds.

The repository-root `.env.example` contains placeholders only. Spring Boot does not load `.env` files automatically; export the values through the local shell, IDE launch configuration, or a secrets manager.
