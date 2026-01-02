# Email Verification + 2FA Auth Demo (Vanilla JS + Node/Express)

A beginner-friendly authentication project that **feels like a real app**, but is still small enough to understand end-to-end.

This repo shows the complete auth story:

- **Sign up** with email verification (4-digit OTP)
- **Sign in** with optional 2FA:
  - Email OTP (4 digits)
  - Authenticator app (TOTP, 6 digits)
  - Backup codes (10 one-time codes)
- **Forgot password** (email OTP + reset)
- **Account settings** (update profile + change password)

It also includes small UX + “production-ish” details beginners usually miss:

- Auto **Unique UserName** suggestion (slug from display name) on **Sign up** + **Account settings**
- “Dirty guard”: if you manually edit Unique UserName, autosuggest stops overwriting it
- OTP **resend** cooldown + simple rate limiting (API returns `retryAfter`)
- “Instructor mode”: if email can’t be sent, the UI shows `debug_code` so you can keep learning

---

## Live: https://twofa-auth-vwrs.onrender.com/

<details><summary><h2>Screenshots</h2></summary>

### Sign-in

![](https://imgur.com/uCNbMQN.png)

### Sign-in with Authenticator

![](https://imgur.com/rmImek0.png)

### Sign-in with Backup Codes

![](https://imgur.com/Oi7b2yz.png)

### Forget Password

![](https://imgur.com/L3nQKDz.png)

### Sing-up

![](https://imgur.com/JFmpJ47.png)

### Dashboard

![](https://imgur.com/BZf8QF2.png)

### Enable Authenticator

![](https://imgur.com/QnrYJik.png)

### Account Setting

![](https://imgur.com/jAkgOl8.png)

</details>

---

## 1) Quick Start (Local)

### Prerequisites

- Node.js (recommended: 18+)
- npm

### Install

```bash
npm install
```

### Configure environment

1. Create a `.env` file with:

```
# Copy to .env (DO NOT commit .env)
# Gmail App Password recommended.

BREVO_API_KEY=
BREVO_FROM=""

PORT=3000

# SMTP settings (defaults are Gmail)
SMTP_USER=
SMTP_PASS=
SMTP_HOST=
SMTP_PORT=
SMTP_SECURE=

# Optional mail settings
# MAIL_SUBJECT=

# SMTP (Brevo relay) (alternative to HTTPS APIs)
SMTP_HOST=
SMTP_PORT=
SMTP_SECURE=
SMTP_USER=
SMTP_PASS=

# Sender address (should be a verified sender in Brevo)
MAIL_FROM=
```

3. Optional: change `PORT` (default is `3000`)

### Run

```bash
npm start
```

Open the URL printed in your terminal, e.g. `http://localhost:3000`.

Important: don’t open `index.html` directly. The UI calls `/api/*` endpoints and needs the server.

### Windows PowerShell tip (change port)

```powershell
$env:PORT=3009; npm start
```

---

## 2) Email Sending (Real Delivery vs Instructor Mode)

When you click **Send code**, the server generates a 4-digit OTP and tries to deliver it.

Delivery options (in order):

1. **Brevo HTTPS API** (recommended for hosting)
2. **SMTP** (works locally, but can be blocked by some hosts)
3. **Instructor / Debug mode** (no email sent; the UI displays the OTP)

### Provider fallback behavior (important)

This is the exact fallback logic used by the server when sending OTP emails:

1. If `BREVO_API_KEY` is set → **try Brevo first**
2. If Brevo fails (or `BREVO_API_KEY` is missing) → **try SMTP**

- SMTP is only attempted if **both** `SMTP_USER` and `SMTP_PASS` are set

3. If SMTP fails (or is not configured) → **Instructor/Debug mode**

- Response includes `delivered: false` and a `debug_code`

If you’re asking “what happens if Brevo fails?” → the app will then try SMTP.

#### How to force a provider (no code changes)

- Force **Brevo-only**: set `BREVO_API_KEY`, and remove/empty `SMTP_USER` + `SMTP_PASS`
- Force **SMTP-only**: remove/empty `BREVO_API_KEY`, and set `SMTP_USER` + `SMTP_PASS`

If you want the opposite order (**SMTP → Brevo → Debug**), that requires a small change in `server.js`.

### Recommended for hosting: Brevo (HTTPS API)

Brevo works on platforms that block outbound SMTP.

Required env var:

- `BREVO_API_KEY`

Recommended sender env var:

- `MAIL_FROM` (example: `Email Verification Demo <your@gmail.com>`)
  - The sender email must be verified in your Brevo account.

Optional:

- `BREVO_FROM` (if set, Brevo will prefer this sender)
- `MAIL_SUBJECT` (custom subject)

### SMTP (local-friendly option)

In `.env`:

- `SMTP_USER` = your Gmail address
- `SMTP_PASS` = a **Gmail App Password** (not your normal password)

### **_Note -- Gmail App Password_**

#### Step-1: Turn on 2-Step Verification

![](https://imgur.com/fgDB517.png)

#### Step-2: Goto App passwords

![](https://imgur.com/pbiBiDQ.png)

OR, visit: https://myaccount.google.com/apppasswords

#### Step-3: Create App

![](https://imgur.com/CKuBgMU.png)

Optional:

- `MAIL_FROM` (example: `Email Verification Demo <your@gmail.com>`)
- `MAIL_SUBJECT`

### Instructor / Debug OTP mode

If email isn’t configured (or delivery fails), OTP endpoints return:

- `delivered: false`
- `debug_code: "1234"`

The frontend shows this code so you can keep learning without setting up email.

---

## 3) Deploy to Render (Beginner Steps)

Render does **not** want you to upload a `.env` file.
Instead, copy env vars into Render:

1. Render Dashboard → your service → **Environment**
2. Add your env vars (do **not** wrap values in quotes)
3. Deploy

Template file you can use as a checklist:

- `.envForRender.example`

Important:

- Don’t set `PORT` on Render (Render injects it automatically)
- Never commit secrets (API keys, SMTP passwords)

---

## 4) Beginner Walkthrough (What You’ll See)

### A) Sign up (email verification)

1. Open **Sign up**
2. Enter **UserName**
3. The app auto-suggests a **Unique UserName** from your name (example: `sagar-biswas`)
4. Enter email → **Send code** → enter the 4-digit OTP
5. Create account

Notes:

- OTPs expire in ~5 minutes
- OTP resend is rate-limited (API returns `retryAfter`)

### B) Sign in (password + optional 2FA)

1. Enter email + password
2. If you enabled a 2FA method, complete one of:
   - Email OTP (4 digits)
   - Authenticator TOTP (6 digits)
   - Backup code (one-time)

### C) Dashboard

After sign-in you can manage:

- **2FA (Email OTP)**
- **Authenticator (TOTP)**
- **Backup codes**

### D) Account settings

- Update profile fields (including Unique UserName)
- Unique UserName can be auto-suggested here too
  - If you type your own Unique UserName manually, suggestions won’t overwrite it
- Change password requires your current password

### E) Forgot password

1. From Sign in, click **Forgot password?**
2. Enter your registered email
3. Send code → enter 4-digit OTP
4. Set a new password
5. Any active sessions for that email are cleared (forces sign-in again)

---

## 5) Project Structure (File Map)

- `index.html` — UI layout (Sign in / Sign up / Forgot password / Dashboard)
- `src/app.js` — frontend logic (fetch to `/api/*`, view switching, autosuggest, forms)
- `src/styles.css` — styling
- `server.js` — Express API, sessions, OTP/TOTP, backup codes, persistence
- `data/users.json` — local JSON “database” (auto-created)

High-level architecture:

```
Browser (index.html + src/app.js)
   |
   | fetch('/api/...')
   v
Node/Express (server.js)
   |
   | reads/writes
   v
data/users.json
```

---

## 6) How It Works (Under the Hood)

### OTP (email codes)

- OTP is **4 digits**, TTL ~5 minutes
- Server stores **only a hash** of the OTP in memory (`otpStore`)
- OTP entries are scoped by purpose (signup/reset/signin)
- Attempts are limited (`MAX_ATTEMPTS`)
- Send has cooldown + simple per-IP limits

### Sessions

- The server issues an HttpOnly cookie named `sid`
- Session data is stored in memory (`sessions` Map)

### TOTP (Authenticator)

- RFC 6238 style (SHA1, 30s step, 6 digits)
- Server creates a Base32 secret and an `otpauth://` URI
- QR generation is supported (uses `qrcode`)

### Backup codes

- Generates 10 one-time codes
- Stores **hashes** only
- Using a backup code consumes it

---

## 7) API Reference (Accurate to This Repo)

### Health

- `GET /api/health`

### Username suggestions

- `GET /api/username/suggest?name=Your%20Name`

### Sign up

- `POST /api/signup/send-code` — send signup OTP
- `POST /api/signup` — create account (requires OTP)

### Forgot password

- `POST /api/password/forgot/send-code` — send reset OTP
- `POST /api/password/forgot/reset` — verify OTP + set new password

### Sign in

- `POST /api/signin/start`
- `POST /api/signin/send-code`
- `POST /api/signin/complete`

### Session

- `GET /api/me` (requires auth)
- `POST /api/signout`

### Account settings (requires auth)

- `POST /api/account/update` — update profile fields
- `POST /api/account/password` — change password

### 2FA settings (requires auth)

- `POST /api/2fa/set`
- `POST /api/2fa/method`

### Authenticator / TOTP (requires auth)

- `POST /api/totp/begin`
- `POST /api/totp/reset-begin`
- `GET /api/totp/qr`
- `POST /api/totp/cancel`
- `POST /api/totp/confirm`

### Backup codes (requires auth)

- `POST /api/backup-codes/enable`
- `POST /api/backup-codes/disable`
- `GET /api/backup-codes/status`

### Lookup helper (requires auth)

- `GET /api/users/by-unique/:unique`

Legacy / generic OTP helpers (used for learning / reuse):

- `POST /api/send` — send OTP for an arbitrary `purpose`
- `POST /api/verify` — verify OTP for an arbitrary `purpose`

---

## 8) Troubleshooting

### “API route not found”

Usually means:

- you opened `index.html` directly (don’t), or
- you started a different server from another folder/port

Fix:

- Start the server from the correct project folder
- Open the exact URL printed by the server

### Port already in use

If the port is busy, set a different one:

```powershell
$env:PORT=3009; npm start
```

### Email not sending

- If you see `debug_code`, delivery failed and the app switched to Instructor mode — this is OK for learning.
- For real delivery on hosting, use **Brevo HTTPS** (`BREVO_API_KEY` + a verified sender).
- For real delivery locally, use a Gmail App Password and restart after editing `.env`.

### No QR code for authenticator

- Ensure `qrcode` is installed (`npm i qrcode`), or
- Use manual setup with the Base32 secret shown in the UI

---

## 9) Production-like polish (What this repo already does)

This is still a learning project, but it includes a few “real world” touches:

- Disables `X-Powered-By`
- Adds basic security/correctness headers
- Avoids caching `/api/*` responses (OTP endpoints are `no-store`)
- Stores OTPs as hashes (not plaintext)

## 10) If you want to make it truly production-ready

High-value checklist:

- Password hashing: replace SHA-256 with **bcrypt / scrypt / Argon2**
- Persistence: replace `data/users.json` with a real DB (Postgres/MySQL/MongoDB)
- Sessions: store sessions in Redis/DB; use HTTPS; set cookie `Secure` + `SameSite`
- CSRF protection (because cookies are used)
- Logging + monitoring (and never leak secrets)
- Email enumeration: consider making forgot-password always return a generic response
- Protect TOTP secrets properly (encrypt-at-rest in a real system)

---

## 11) Instructor Mode (Teaching Script + Exercises)

### A) 30–45 minute teaching flow

1. Show Sign up with email OTP (OTP TTL + attempts)
2. Show Unique UserName auto-suggestion (slugifying + uniqueness)
3. Sign in and explain sessions (HttpOnly cookie `sid`)
4. Enable Email 2FA → sign out → sign in again → complete OTP
5. Enable TOTP and explain `otpauth://` + 30s window
6. Enable backup codes and explain “one-time” behavior
7. Show Account settings update + password change
8. Show Forgot password flow + forced sign-out of active sessions

### B) Beginner exercises (safe extensions)

1. Add `GET /api/version` returning app name + version.
2. Improve forgot-password to avoid email enumeration (always respond `ok: true`).
3. Add `SameSite=Lax` cookie attribute in the session cookie helper.
4. Replace password hashing with bcrypt.
5. Add tests for OTP expiry + attempt limits + backup code consumption.




