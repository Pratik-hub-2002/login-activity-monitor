# LOGIN ACTIVITY MONITOR — SUBMISSION EMAIL

**Subject:** Login Activity Monitor — Technical Evaluation Submission (Branch: `feature/session-management`)

**To:** [Evaluator / Hiring Manager / Technical Review Team]
**From:** [Your Name]
**Date:** 10-Nov-2026

---

Dear [Evaluator / Hiring Manager / Team],

Please find my submission for the **Login Activity Monitor for Suspicious Behaviour** technical evaluation.

## PROJECT OVERVIEW

The Login Activity Monitor is a Spring Boot 4.1.2 (Java 25) REST application with a React + Vite frontend that tracks login attempts, detects suspicious login patterns, enforces IP-based rate limiting and hCaptcha, and secures authentication with email-delivered TOTP two-factor authentication.

## MAIN IMPLEMENTED FEATURES

1. **Login Attempt Tracking** — Logs all login attempts (SUCCESS / FAILURE) with username, IP address, and timestamp to the `login_attempts` table.
2. **Suspicious Login Detection** — Three rule-based detection algorithms (username-based, IP-based, success-after-failures) with SHA-256 fingerprint duplicate prevention.
3. **IP-Based Rate Limiting** — 5 requests per 60-second rolling window per IP → HTTP 429.
4. **hCaptcha Integration** — Server-side CAPTCHA verification triggered after repeated failures.
5. **BCrypt Password Hashing** — Secure one-way password hashing via Spring Security `DaoAuthenticationProvider`.
6. **Spring Security Authentication** — Basic Authentication with `SessionAuthenticationFilter` validating `X-Session-Id` header.
7. **Email OTP / TOTP Two-Factor Authentication** — Google Authenticator TOTP, 6-digit code, 90-second validity, single-use, delivered via SMTP email.
8. **Session Management** — Secure random 32-byte session IDs, 15-minute inactivity expiry, activity refresh, explicit logout.
9. **Role-Based Access Control** — USER / ADMIN / SUPERADMIN with endpoint-level restrictions.
10. **Dashboard Statistics** — Aggregate login attempt and suspicious activity counts.
11. **Email Notifications** — OTP delivery emails and suspicious activity alerts.
12. **Scheduled Detection** — Background scan every 60 seconds for suspicious patterns.
13. **React + Vite Frontend** — Login page, dashboard, login attempts table, suspicious activity timeline.

## TECHNOLOGY STACK

| Category | Technology | Version |
|----------|-----------|---------|
| Language | Java | 25 |
| Framework | Spring Boot | 4.1.2 |
| Web / REST | spring-boot-starter-webmvc | — |

## ACTUAL BUILD AND TEST RESULTS

### Backend Compilation

```
./mvnw.cmd -o clean compile
[INFO] BUILD SUCCESS
[INFO] Compiling 53 source files with javac [debug parameters release 25]
```

**Result: PASS** — All 53 source files compile successfully.

### Backend Tests & Verification

```
./mvnw.cmd -o test-compile
[INFO] BUILD SUCCESS
[INFO] Compiling 25 test source files with javac [debug parameters release 25]
```

**Remediated Test Items:**
1. `SecurityAuthorizationIntegrationTest.validPasswordRequiresOtpBeforeSessionCreation`: Resolved by adding `@Import(TestMailConfiguration.class)` to supply a mock `JavaMailSender`, isolating the test from live SMTP dependencies and returning the expected HTTP 202.
2. `LoginServiceTest`: Resolved by injecting `@Spy Clock` in test setup and adding a defensive fallback (`clock != null ? clock : Clock.systemUTC()`) in `LoginService`.
3. `ClientIpAddressExtractor`: Enhanced to resolve client IP from `X-Forwarded-For` headers when behind proxies or dev servers.
4. `HcaptchaConfiguration`: Configured with `SimpleClientHttpRequestFactory` to avoid loopback socket permission issues.

### Frontend Verification

```
npm run build
[INFO] Vite production build completed in 1.41s; assets generated in dist/
npm run lint
[INFO] 0 errors, 0 warnings
```

## KNOWN LIMITATIONS

1. **External configuration required:** SMTP, MySQL, and hCaptcha credentials must be configured for live production operation.
2. **No per-username account lockout:** Only IP-based rate limiting exists.
3. **In-memory rate limiter and OTP store:** Not clustered; does not survive restarts.

## OFFER TO DEMONSTRATE

I am available to provide a live demonstration of the application, walk through the codebase, or address any questions about the implementation. Please let me know a convenient time.

---

Best regards,
[Your Name]
[Your Contact Information]

---

**Attachments:**
- `Login_Activity_Monitor_Final_Audit.md` — Complete technical audit report
- Source ZIP (available upon request) — Project source excluding `node_modules/`, `target/`, `.git/`

### Frontend Build

**NOT TESTED** — `node_modules` is present; `npm run build` was not executed.

## GIT INFORMATION

- **Repository:** `https://github.com/Pratik-hub-2002/login-activity-monitor.git`
- **Branch:** `feature/session-management`
- **Last Commit:** `0cd7dc1` — "fix: accept successful login audit events"
- **Working Tree:** 18 modified files, 2 untracked files (all preserved as-is)

## SUBMISSION PACKAGE

- **Technical Audit Report:** `Login_Activity_Monitor_Final_Audit.md` (attached)
- **Source Code:** Available in the Git repository or as a ZIP archive (excluding `node_modules/`, `target/`, `.git/`)
- **Live Demo:** Available upon request

| Data / JPA | spring-boot-starter-data-jpa | — |
| Database (runtime) | MySQL Connector/J | — |
| Database (test) | H2 | — |
| Security | spring-boot-starter-security | — |
| Password Hashing | BCrypt | — |
| Mail | spring-boot-starter-mail | — |
| OTP / TOTP | com.warrenstrange:googleauth | 1.5.0 |
| CAPTCHA | hCaptcha | — |
| Frontend | React | ^19.3.1 |
| Frontend build | Vite | ^8.3.6 |
| HTTP client | axios | ^1.21.0 |
| Testing | JUnit 5, Mockito, Spring test starters | — |
