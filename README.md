# Email Verification + 2FA Auth Demo (Vanilla JS + Node/Express)

A beginner-friendly authentication project that **looks like a real app**, but stays small enough to understand in one sitting.

## Pictures

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

This repo demonstrates:

- Email verification during **Sign up** (4‑digit OTP)
- Sign in with **optional 2FA**:
  - Email OTP (4 digits)
  - Authenticator app **TOTP** (6 digits)
  - **Backup codes** (10 one‑time codes)
- **Forgot password** using email verification (4‑digit OTP)
- **Account settings** after sign‑in:
  - Update profile details (UserName, Unique UserName, phone, email)
  - Change password (requires current password)
- Small but important UX details:
  - Auto **Unique UserName suggestion** (slug from name) on **Sign up** and **Account settings**
  - Suggestion “dirty” guard: if you manually edit Unique UserName, it won’t keep overwriting your value
  - Resend cooldown + rate‑limit response includes `retryAfter`
  - “Debug OTP mode” for learning locally when SMTP isn’t configured

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

1. Copy `.env.example` → `.env`
2. Optional: change `PORT` (default is `3000`)

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

## 2) Email Sending (SMTP) — Real vs Debug Mode

This project tries to send OTPs via SMTP using Nodemailer.

### Real email (recommended)

In `.env`:

- `SMTP_USER` = your Gmail address
- `SMTP_PASS` = a **Gmail App Password** (not your normal password)

### **_Note: Gmail App Password_**

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

### Debug OTP mode (perfect for beginners)

If SMTP isn’t configured (or fails), OTP endpoints return:

- `delivered: false`
- `debug_code: "1234"`

The frontend shows this code so you can continue learning without setting up email.

---

## 3) Optional: QR Codes for Authenticator Apps

TOTP works even without QR generation (you can always copy the Base32 secret), but if you want QR images:

```bash
npm i qrcode
```

If `qrcode` isn’t installed, QR endpoints respond with `qrDataUrl: null` (and `/api/totp/qr` returns 501).

---

## 4) What You’ll See in the UI (Beginner Walkthrough)

### A) Sign up (Email verification)

1. Go to **Sign up**
2. Enter **UserName**
3. The app auto-suggests **Unique UserName** from your name (example: `sagar-biswas`)
4. Enter email → click **Send code** → enter the 4-digit OTP
5. Create account

Notes:

- OTPs expire in ~5 minutes
- Resend is rate-limited (you’ll see `retryAfter`)

### B) Sign in (Password + optional 2FA)

1. Enter email + password
2. If you enabled a verification method, you’ll be asked to complete one of:
   - Email OTP (4 digits)
   - Authenticator TOTP (6 digits)
   - Backup code (one-time)

### C) Dashboard

After sign-in you can toggle:

- **2FA (Email)**
- **Authenticator (TOTP)**
- **Backup codes**

You can also open **Account settings**.

### D) Account settings

- Update profile fields (including Unique UserName)
- The Unique UserName can also be auto-suggested here
  - If you type your own Unique UserName manually, suggestions won’t overwrite it
- Change password requires your current password

### E) Forgot password

From Sign in, click **Forgot password?**

1. Enter your registered email
2. Send code → enter 4-digit OTP
3. Set a new password
4. Any active sessions for that email are cleared (forces sign-in again)

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

### OTP (Email codes)

- OTP is **4 digits**, TTL ~5 minutes
- The server stores **only a hash** of the OTP in memory (`otpStore`)
- OTP keys are scoped by purpose: `"signup:email"`, `"reset:email"`, etc.
- Attempts are limited (`MAX_ATTEMPTS`)
- Send has cooldown and simple per-IP limits

### Sessions

- The server issues an HttpOnly cookie named `sid`
- Session data is stored in memory (`sessions` Map)
- This is intentionally simple for learning

### TOTP (Authenticator)

- RFC 6238 style (SHA1, 30s step, 6 digits)
- The server creates a Base32 secret and an `otpauth://` URI
- QR generation is optional (see `qrcode` section)

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

This usually means:

- you opened `index.html` directly (don’t), or
- you started a different/older server on another port/folder

Fix:

- Start the server from the correct project folder
- Open the exact URL printed by the server

### Port already in use

If port is busy, set a different one:

```powershell
$env:PORT=3009; npm start
```

### Email not sending

- If you see `debug_code`, SMTP isn’t configured or failed — this is OK for learning.
- For real delivery, use Gmail App Password and restart after editing `.env`.

### No QR code for authenticator

- Install `qrcode` (`npm i qrcode`), or
- use manual setup with the Base32 secret shown in the modal

---

## 9) Production-Like Notes (What to Improve Before Real Deployment)

This project is intentionally simple for learning. If you want to make it production-ready, here’s a high-value checklist:

- Password hashing: replace SHA-256 with **bcrypt / scrypt / Argon2**
- Persistence: replace `data/users.json` with a real DB (Postgres, MySQL, MongoDB)
- Sessions: store sessions in Redis / DB; set cookie `Secure` + `SameSite` (and use HTTPS)
- CSRF protection (because cookies are used)
- Logging + monitoring (and avoid leaking secrets in logs)
- Email enumeration: forgot-password currently reveals “Email not registered” (consider returning a generic response)
- Secret handling: protect TOTP secrets (at least encrypt-at-rest in a real system)

---

## 10) Instructor Mode (Teaching Script + Exercises)

### A) 30–45 minute teaching flow

1. Show Sign up with email OTP (explain OTP TTL + attempts)
2. Show Unique UserName auto-suggestion (slugifying + uniqueness)
3. Sign in and explain sessions (HttpOnly cookie `sid`)
4. Enable Email 2FA → sign out → sign in again → complete OTP
5. Enable TOTP and explain `otpauth://` + 30s windows
6. Enable backup codes and explain “one-time” behavior
7. Show Account settings update + password change
8. Show Forgot password flow + forced sign-out of active sessions

### B) Beginner exercises (safe extensions)

1. Add `GET /api/version` returning app name + version.
2. Improve forgot-password to avoid email enumeration (always respond `ok: true`).
3. Add `SameSite=Lax` cookie attribute in the session cookie helper.
4. Replace password hashing with bcrypt.
5. Add tests for:
   - slug/Unique UserName validation
   - OTP verify expiry + attempt limits
   - backup code normalization
