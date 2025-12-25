const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

require("dotenv").config();

const express = require("express");
const nodemailer = require("nodemailer");

let QRCode = null;
try {
  // Optional dependency used to generate QR codes for authenticator apps.
  // Install with: npm i qrcode
  QRCode = require("qrcode");
} catch {
  QRCode = null;
}

const app = express();
app.disable("x-powered-by");
app.use(express.json());

// Small security + correctness headers (keeps beginner apps safer by default)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  if (String(req.path || "").startsWith("/api/")) {
    // Avoid caching OTP / security responses
    res.setHeader("Cache-Control", "no-store");
  }
  next();
});

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const USERS_PATH = path.join(DATA_DIR, "users.json");

// Serve your existing static files
app.use("/src", express.static(path.join(ROOT, "src")));
app.use("/", express.static(ROOT));

// Simple health check (useful for beginners)
app.get("/api/health", (_req, res) => {
  return res.json({ ok: true, status: "ok", time: new Date().toISOString() });
});

const OTP_LENGTH = 4;
const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;

const SEND_EMAIL_COOLDOWN_MS = 30 * 1000; // per-email minimum time between sends
const SEND_IP_WINDOW_MS = 10 * 60 * 1000;
const SEND_IP_MAX_IN_WINDOW = 25;

/** @type {Map<string, { codeHash: string, expiresAt: number, attempts: number }>} */
const otpStore = new Map();

/** @type {Map<string, { email: string, expiresAt: number, method: 'email' | 'totp' | 'backup' }>} */
const signInAttempts = new Map();

/** @type {Map<string, { email: string, expiresAt: number }>} */
const sessions = new Map();

/** @type {Map<string, { lastSentAt: number }>} */
const emailSendState = new Map();

/** @type {Map<string, { windowStart: number, count: number }>} */
const ipSendState = new Map();

const normalizeEmail = (email) =>
  String(email || "")
    .trim()
    .toLowerCase();

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const TWO_FACTOR_MODES = new Set(["none", "email", "totp"]);

const getTwoFactorMode = (user) => {
  const mode = String(user?.twoFactorMode || "").toLowerCase();
  if (TWO_FACTOR_MODES.has(mode)) return mode;
  return user?.twoFactorEnabled ? "email" : "none";
};

const setTwoFactorMode = (user, mode) => {
  const m = String(mode || "none").toLowerCase();
  const finalMode = TWO_FACTOR_MODES.has(m) ? m : "none";
  user.twoFactorMode = finalMode;
  // Backward-compatible: this boolean represents EMAIL 2FA only.
  user.twoFactorEnabled = finalMode === "email";
};

// --- TOTP (RFC 6238, SHA1, 30s step, 6 digits) ---
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const base32Normalize = (s) =>
  String(s || "")
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/=+$/g, "")
    .replace(/[^A-Z2-7]/g, "");

const base32ToBuffer = (secret) => {
  const s = base32Normalize(secret);
  if (!s) return Buffer.alloc(0);
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
};

const bufferToBase32 = (buf) => {
  const b = Buffer.from(buf || Buffer.alloc(0));
  if (!b.length) return "";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of b) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
};

const generateTotpSecret = () => bufferToBase32(crypto.randomBytes(20));

const totpNow = ({
  secret,
  timeMs = Date.now(),
  stepSeconds = 30,
  digits = 6,
}) => {
  const key = base32ToBuffer(secret);
  if (!key.length) return null;

  const counter = Math.floor(timeMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  const code = String(bin % mod).padStart(digits, "0");
  return code;
};

const verifyTotp = ({ secret, code, window = 1 }) => {
  const c = String(code || "").trim();
  if (!/^\d{6}$/.test(c)) return false;
  for (let i = -window; i <= window; i++) {
    const candidate = totpNow({ secret, timeMs: Date.now() + i * 30 * 1000 });
    if (
      candidate &&
      crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(c))
    ) {
      return true;
    }
  }
  return false;
};

/** @type {Map<string, { secret: string, issuer: string, otpauthUri: string, createdAt: number, qrDataUrl: string | null }>} */
const pendingTotpSetups = new Map();

const PENDING_TOTP_TTL_MS = 10 * 60 * 1000;

const buildTotpOtpauthUri = ({ issuer, email, secret }) => {
  const label = `${issuer}:${email}`;
  return `otpauth://totp/${encodeURIComponent(
    label
  )}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=SHA1&digits=6&period=30`;
};

const getOrCreatePendingTotpSetup = ({ email, issuer, forceNew = false }) => {
  const existing = pendingTotpSetups.get(email);
  if (
    !forceNew &&
    existing &&
    Date.now() - existing.createdAt < PENDING_TOTP_TTL_MS
  ) {
    return existing;
  }

  const secret = generateTotpSecret();
  const otpauthUri = buildTotpOtpauthUri({ issuer, email, secret });
  const payload = {
    secret,
    issuer,
    otpauthUri,
    createdAt: Date.now(),
    qrDataUrl: null,
  };
  pendingTotpSetups.set(email, payload);
  return payload;
};

const isValidPhone = (phone) => {
  const p = String(phone || "").replace(/\s+/g, "");
  return /^\+?[0-9]{8,15}$/.test(p);
};

const sanitizePurpose = (purpose) => {
  const p = String(purpose || "generic").trim();
  if (!p) return "generic";
  // only allow a safe subset
  const safe = p.replace(/[^a-zA-Z0-9:_-]/g, "").slice(0, 64);
  return safe || "generic";
};

const otpKey = ({ email, purpose }) => `${sanitizePurpose(purpose)}:${email}`;

// --- Backup codes (10 one-time codes) ---
const BACKUP_CODES_COUNT = 10;

function ensureBackupCodesShape(user) {
  if (!user) return;
  if (!user.backupCodes || typeof user.backupCodes !== "object") {
    user.backupCodes = { createdAt: "", hashes: [] };
    return;
  }
  if (typeof user.backupCodes.createdAt !== "string")
    user.backupCodes.createdAt = "";
  if (!Array.isArray(user.backupCodes.hashes)) user.backupCodes.hashes = [];
}

function backupCodesRemaining(user) {
  return Array.isArray(user?.backupCodes?.hashes)
    ? user.backupCodes.hashes.length
    : 0;
}

function generateBackupCode() {
  // readable one-time code (letters+numbers), intended for download
  const raw = crypto.randomBytes(8).toString("hex"); // 16 hex chars
  return `${raw.slice(0, 5)}-${raw.slice(5, 10)}-${raw.slice(
    10,
    15
  )}`.toUpperCase();
}

function setBackupCodes(user, plainCodes) {
  ensureBackupCodesShape(user);
  const codes = Array.isArray(plainCodes) ? plainCodes : [];
  user.backupCodes.createdAt = new Date().toISOString();
  user.backupCodes.hashes = codes.map((c) =>
    crypto.createHash("sha256").update(String(c)).digest("hex")
  );
}

function clearBackupCodes(user) {
  ensureBackupCodesShape(user);
  user.backupCodes.createdAt = "";
  user.backupCodes.hashes = [];
}

function normalizeBackupCodeInput(input) {
  const raw = String(input || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "");
  if (!raw) return "";

  // Keep only safe characters.
  const safe = raw.replace(/[^A-Z0-9-]/g, "");
  const compact = safe.replace(/-/g, "");

  // Accept codes pasted without hyphens (15 hex chars) and normalize.
  if (/^[0-9A-F]{15}$/.test(compact)) {
    return `${compact.slice(0, 5)}-${compact.slice(5, 10)}-${compact.slice(
      10,
      15
    )}`;
  }

  return safe;
}

function consumeBackupCode(user, plainCode) {
  ensureBackupCodesShape(user);
  const normalized = normalizeBackupCodeInput(plainCode);
  if (!normalized) return false;
  if (
    !Array.isArray(user.backupCodes.hashes) ||
    user.backupCodes.hashes.length === 0
  )
    return false;

  const hashHex = crypto.createHash("sha256").update(normalized).digest("hex");

  const hashBuf = Buffer.from(hashHex, "hex");
  const idx = user.backupCodes.hashes.findIndex((h) => {
    try {
      const hBuf = Buffer.from(String(h || ""), "hex");
      if (hBuf.length !== hashBuf.length) return false;
      return crypto.timingSafeEqual(hBuf, hashBuf);
    } catch {
      return String(h || "") === hashHex;
    }
  });

  if (idx === -1) return false;
  user.backupCodes.hashes.splice(idx, 1);
  return true;
}

const ensureUsersFile = () => {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_PATH)) {
    fs.writeFileSync(
      USERS_PATH,
      JSON.stringify({ users: [] }, null, 2),
      "utf-8"
    );
  }
};

const loadUsers = () => {
  ensureUsersFile();
  try {
    const raw = fs.readFileSync(USERS_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    const users = Array.isArray(parsed?.users) ? parsed.users : [];
    // Migrate older records in-memory (saved back when modified).
    for (const u of users) {
      if (!u) continue;
      if (!u.twoFactorMode) {
        const mode = u.twoFactorEnabled ? "email" : "none";
        u.twoFactorMode = mode;
      }
      if (typeof u.totpSecret !== "string") u.totpSecret = "";
      ensureBackupCodesShape(u);
    }
    return users;
  } catch {
    return [];
  }
};

const saveUsers = (users) => {
  ensureUsersFile();
  fs.writeFileSync(USERS_PATH, JSON.stringify({ users }, null, 2), "utf-8");
};

const sha256Hex = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const slugify = (value) => {
  const s = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24);
  return s || "user";
};

const cookieParse = (cookieHeader) => {
  const out = {};
  const str = String(cookieHeader || "");
  if (!str) return out;
  for (const part of str.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
};

const setCookie = (res, name, value, opts = {}) => {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push("Path=/");
  parts.push("HttpOnly");
  // For local dev over http, don't force Secure
  if (opts.maxAgeSeconds != null) parts.push(`Max-Age=${opts.maxAgeSeconds}`);
  res.setHeader("Set-Cookie", parts.join("; "));
};

const clearCookie = (res, name) => {
  res.setHeader("Set-Cookie", `${name}=; Path=/; HttpOnly; Max-Age=0`);
};

const requireAuth = (req, res, next) => {
  const cookies = cookieParse(req.headers.cookie);
  const sid = cookies.sid;
  if (!sid) return res.status(401).json({ ok: false, error: "Not signed in." });
  const session = sessions.get(sid);
  if (!session)
    return res.status(401).json({ ok: false, error: "Not signed in." });
  if (Date.now() > session.expiresAt) {
    sessions.delete(sid);
    clearCookie(res, "sid");
    return res.status(401).json({ ok: false, error: "Session expired." });
  }
  req.authEmail = session.email;
  req.authSid = sid;
  next();
};

const clientIp = (req) => {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || "unknown";
};

const retryAfterSeconds = (ms) => Math.max(1, Math.ceil(ms / 1000));

const checkSendLimits = ({ email, ip }) => {
  const now = Date.now();

  const emailState = emailSendState.get(email);
  if (emailState && now - emailState.lastSentAt < SEND_EMAIL_COOLDOWN_MS) {
    const msLeft = SEND_EMAIL_COOLDOWN_MS - (now - emailState.lastSentAt);
    return {
      ok: false,
      status: 429,
      error: "Please wait before requesting another code.",
      retryAfter: retryAfterSeconds(msLeft),
    };
  }

  const ipState = ipSendState.get(ip);
  if (!ipState || now - ipState.windowStart >= SEND_IP_WINDOW_MS) {
    ipSendState.set(ip, { windowStart: now, count: 0 });
  }

  const updated = ipSendState.get(ip);
  if (updated.count >= SEND_IP_MAX_IN_WINDOW) {
    const msLeft = SEND_IP_WINDOW_MS - (now - updated.windowStart);
    return {
      ok: false,
      status: 429,
      error: "Too many requests. Please try again later.",
      retryAfter: retryAfterSeconds(msLeft),
    };
  }

  return { ok: true };
};

const noteSend = ({ email, ip }) => {
  const now = Date.now();
  emailSendState.set(email, { lastSentAt: now });

  const ipState = ipSendState.get(ip);
  if (ipState) {
    ipState.count += 1;
    ipSendState.set(ip, ipState);
  } else {
    ipSendState.set(ip, { windowStart: now, count: 1 });
  }
};

// Periodic cleanup (keeps memory bounded)
setInterval(() => {
  const now = Date.now();
  for (const [email, entry] of otpStore.entries()) {
    if (now > entry.expiresAt + 60 * 1000) otpStore.delete(email);
  }
  for (const [email, state] of emailSendState.entries()) {
    if (now - state.lastSentAt > 60 * 60 * 1000) emailSendState.delete(email);
  }
  for (const [ip, state] of ipSendState.entries()) {
    if (now - state.windowStart > SEND_IP_WINDOW_MS * 2) ipSendState.delete(ip);
  }
}, 60 * 1000).unref?.();

const randomOtp = () => {
  // 4-digit numeric code (matches your UI)
  const max = 10 ** OTP_LENGTH;
  const n = crypto.randomInt(0, max);
  return String(n).padStart(OTP_LENGTH, "0");
};

const sha256 = (value) => sha256Hex(value);

const getMailer = async () => {
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!user || !pass) return null;

  // Gmail SMTP defaults; can be overridden via env
  const host = process.env.SMTP_HOST || "smtp.gmail.com";
  const port = Number(process.env.SMTP_PORT || 465);
  const secure = String(process.env.SMTP_SECURE || "true") === "true";

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });

  // Light sanity check (does not send)
  try {
    await transporter.verify();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn("SMTP verify failed; falling back to debug OTP:", msg);
    return null;
  }
  return transporter;
};

const sendOtpEmail = async ({ email, purpose, req }) => {
  const ip = clientIp(req);
  const limit = checkSendLimits({ email, ip });
  if (!limit.ok) {
    return {
      ok: false,
      status: limit.status,
      payload: { ok: false, error: limit.error, retryAfter: limit.retryAfter },
    };
  }

  const code = randomOtp();
  const expiresAt = Date.now() + OTP_TTL_MS;
  otpStore.set(otpKey({ email, purpose }), {
    codeHash: sha256(code),
    expiresAt,
    attempts: 0,
  });

  noteSend({ email, ip });

  const transporter = await getMailer().catch(() => null);
  if (!transporter) {
    return {
      ok: true,
      status: 200,
      payload: { ok: true, delivered: false, debug_code: code },
    };
  }

  const pickMailFrom = () => {
    const raw = String(process.env.MAIL_FROM || "").trim();
    const fallback = String(process.env.SMTP_USER || "").trim();
    if (!raw) return fallback;

    // Very small validation: if it looks like a "Name <email>" address,
    // ensure it has a closing '>' so nodemailer doesn't throw on a typo.
    if (raw.includes("<") && !raw.includes(">")) return fallback;
    return raw;
  };

  const from = pickMailFrom();
  const subject = process.env.MAIL_SUBJECT || "Your verification code";
  const text = `Your verification code is: ${code}\n\nThis code expires in 5 minutes.`;

  await transporter.sendMail({ from, to: email, subject, text });
  return { ok: true, status: 200, payload: { ok: true, delivered: true } };
};

app.post("/api/send", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const purpose = sanitizePurpose(req.body?.purpose || "generic");
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Invalid email." });
    }

    const result = await sendOtpEmail({ email, purpose, req });
    return res.status(result.status).json(result.payload);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to send.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/verify", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const purpose = sanitizePurpose(req.body?.purpose || "generic");
  const code = String(req.body?.code || "").trim();

  if (!isValidEmail(email)) {
    return res.status(400).json({ ok: false, error: "Invalid email." });
  }
  if (!/^\d{4}$/.test(code)) {
    return res.status(400).json({ ok: false, error: "Invalid code." });
  }

  const entry = otpStore.get(otpKey({ email, purpose }));
  if (!entry) {
    return res
      .status(400)
      .json({ ok: false, error: "No code sent for this email." });
  }

  if (Date.now() > entry.expiresAt) {
    otpStore.delete(otpKey({ email, purpose }));
    return res
      .status(400)
      .json({ ok: false, error: "Code expired. Please resend." });
  }

  if (entry.attempts >= MAX_ATTEMPTS) {
    otpStore.delete(otpKey({ email, purpose }));
    return res
      .status(429)
      .json({ ok: false, error: "Too many attempts. Please resend." });
  }

  entry.attempts += 1;
  if (sha256(code) !== entry.codeHash) {
    otpStore.set(otpKey({ email, purpose }), entry);
    return res.status(400).json({ ok: false, error: "Incorrect code." });
  }

  otpStore.delete(otpKey({ email, purpose }));
  return res.json({ ok: true });
});

app.get("/api/username/suggest", (req, res) => {
  const name = String(req.query?.name || "");
  const base = slugify(name);
  const users = loadUsers();
  const taken = new Set(
    users.map((u) => String(u.uniqueUsername || "").toLowerCase())
  );

  const suggestions = [];
  for (let i = 0; i < 15 && suggestions.length < 5; i++) {
    const candidate = i === 0 ? base : `${base}${i}`;
    if (!taken.has(candidate.toLowerCase())) suggestions.push(candidate);
  }
  return res.json({ ok: true, suggested: suggestions[0] || base, suggestions });
});

app.post("/api/signup/send-code", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Invalid email." });
    }
    const result = await sendOtpEmail({ email, purpose: "signup", req });
    return res.status(result.status).json(result.payload);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to send.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/signup", (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const uniqueUsername = String(req.body?.uniqueUsername || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");
    const code = String(req.body?.code || "").trim();

    if (!username)
      return res
        .status(400)
        .json({ ok: false, error: "UserName is required." });
    if (!uniqueUsername)
      return res
        .status(400)
        .json({ ok: false, error: "Unique UserName is required." });
    if (!isValidPhone(phone))
      return res
        .status(400)
        .json({ ok: false, error: "Invalid phone number." });
    if (!isValidEmail(email))
      return res.status(400).json({ ok: false, error: "Invalid email." });
    if (!password || password.length < 6)
      return res
        .status(400)
        .json({ ok: false, error: "Password must be at least 6 characters." });
    if (!/^\d{4}$/.test(code))
      return res
        .status(400)
        .json({ ok: false, error: "Invalid verification code." });

    // Verify signup OTP
    const entry = otpStore.get(otpKey({ email, purpose: "signup" }));
    if (!entry)
      return res
        .status(400)
        .json({ ok: false, error: "Please send a verification code first." });
    if (Date.now() > entry.expiresAt) {
      otpStore.delete(otpKey({ email, purpose: "signup" }));
      return res
        .status(400)
        .json({ ok: false, error: "Code expired. Please resend." });
    }
    if (sha256(code) !== entry.codeHash) {
      entry.attempts += 1;
      otpStore.set(otpKey({ email, purpose: "signup" }), entry);
      return res.status(400).json({ ok: false, error: "Incorrect code." });
    }
    otpStore.delete(otpKey({ email, purpose: "signup" }));

    const users = loadUsers();
    const emailTaken = users.some((u) => normalizeEmail(u.email) === email);
    if (emailTaken)
      return res
        .status(409)
        .json({ ok: false, error: "Email already registered." });
    const uniqueTaken = users.some(
      (u) =>
        String(u.uniqueUsername || "").toLowerCase() ===
        uniqueUsername.toLowerCase()
    );
    if (uniqueTaken)
      return res
        .status(409)
        .json({ ok: false, error: "Unique UserName already taken." });

    const user = {
      id: crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex"),
      username,
      uniqueUsername,
      phone,
      email,
      passwordHash: sha256(password),
      twoFactorEnabled: false,
      twoFactorMode: "none",
      totpSecret: "",
      backupCodes: { createdAt: "", hashes: [] },
      createdAt: new Date().toISOString(),
    };

    users.push(user);
    saveUsers(users);

    return res.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Signup failed.";
    return res.status(500).json({ ok: false, error: message });
  }
});

// --- Forgot password (email verification) ---
app.post("/api/password/forgot/send-code", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Invalid email." });
    }

    const users = loadUsers();
    const user = users.find((u) => normalizeEmail(u.email) === email);
    if (!user) {
      return res
        .status(404)
        .json({ ok: false, error: "Email not registered." });
    }

    const result = await sendOtpEmail({ email, purpose: "reset", req });
    return res.status(result.status).json(result.payload);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to send.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/password/forgot/reset", (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!isValidEmail(email))
      return res.status(400).json({ ok: false, error: "Invalid email." });
    if (!/^\d{4}$/.test(code))
      return res
        .status(400)
        .json({ ok: false, error: "Invalid verification code." });
    if (!newPassword || newPassword.length < 6)
      return res.status(400).json({
        ok: false,
        error: "New password must be at least 6 characters.",
      });

    const users = loadUsers();
    const idx = users.findIndex((u) => normalizeEmail(u.email) === email);
    if (idx === -1)
      return res
        .status(404)
        .json({ ok: false, error: "Email not registered." });

    const key = otpKey({ email, purpose: "reset" });
    const entry = otpStore.get(key);
    if (!entry)
      return res.status(400).json({
        ok: false,
        error: "Please send a verification code first.",
      });
    if (Date.now() > entry.expiresAt) {
      otpStore.delete(key);
      return res
        .status(400)
        .json({ ok: false, error: "Code expired. Please resend." });
    }
    if (entry.attempts >= MAX_ATTEMPTS) {
      otpStore.delete(key);
      return res
        .status(429)
        .json({ ok: false, error: "Too many attempts. Please resend." });
    }
    if (sha256(code) !== entry.codeHash) {
      entry.attempts += 1;
      otpStore.set(key, entry);
      return res.status(400).json({ ok: false, error: "Incorrect code." });
    }
    otpStore.delete(key);

    users[idx].passwordHash = sha256(newPassword);
    saveUsers(users);

    // Sign out any active sessions for this email.
    for (const [sid, session] of sessions.entries()) {
      if (normalizeEmail(session?.email) === email) sessions.delete(sid);
    }

    return res.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Reset failed.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/signin/start", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");
  if (!isValidEmail(email))
    return res.status(400).json({ ok: false, error: "Invalid email." });
  if (!password)
    return res.status(400).json({ ok: false, error: "Password is required." });

  const users = loadUsers();
  const user = users.find((u) => normalizeEmail(u.email) === email);
  if (!user || user.passwordHash !== sha256(password)) {
    return res
      .status(401)
      .json({ ok: false, error: "Invalid email or password." });
  }

  const twoFactorMode = getTwoFactorMode(user);
  const bcRemaining = backupCodesRemaining(user);

  if (twoFactorMode === "none" && bcRemaining > 0) {
    // Backup codes are enabled: require a backup code as the sign-in verification step.
    const attemptId =
      crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex");
    signInAttempts.set(attemptId, {
      email,
      expiresAt: Date.now() + 3 * 60 * 1000,
      method: "backup",
    });
    return res.json({
      ok: true,
      requires2fa: true,
      method: "backup",
      attemptId,
      backupCodesAvailable: true,
      backupCodesRemaining: bcRemaining,
      backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
    });
  }

  if (twoFactorMode === "none") {
    const sid = crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex");
    sessions.set(sid, { email, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
    setCookie(res, "sid", sid, { maxAgeSeconds: 24 * 60 * 60 });
    return res.json({
      ok: true,
      requires2fa: false,
      user: {
        username: user.username,
        phone: user.phone,
        email: user.email,
        uniqueUsername: user.uniqueUsername,
        twoFactorEnabled: !!user.twoFactorEnabled,
        twoFactorMode,
        hasTotpSecret: !!String(user.totpSecret || ""),
        backupCodesRemaining: bcRemaining,
        backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
      },
    });
  }

  if (twoFactorMode === "totp" && !String(user.totpSecret || "")) {
    // Safety: if user is configured to use TOTP but has no secret, fall back to no 2FA.
    setTwoFactorMode(user, "none");
    saveUsers(users);
    const sid = crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex");
    sessions.set(sid, { email, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
    setCookie(res, "sid", sid, { maxAgeSeconds: 24 * 60 * 60 });
    return res.json({
      ok: true,
      requires2fa: false,
      user: {
        username: user.username,
        phone: user.phone,
        email: user.email,
        uniqueUsername: user.uniqueUsername,
        twoFactorEnabled: !!user.twoFactorEnabled,
        twoFactorMode: "none",
        hasTotpSecret: false,
        backupCodesRemaining: backupCodesRemaining(user),
        backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
      },
    });
  }

  const attemptId =
    crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex");
  signInAttempts.set(attemptId, {
    email,
    expiresAt: Date.now() + 3 * 60 * 1000,
    method: twoFactorMode === "totp" ? "totp" : "email",
  });
  return res.json({
    ok: true,
    requires2fa: true,
    method: twoFactorMode === "totp" ? "totp" : "email",
    attemptId,
    backupCodesAvailable: bcRemaining > 0,
    backupCodesRemaining: bcRemaining,
    backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
  });
});

app.post("/api/signin/send-code", async (req, res) => {
  const attemptId = String(req.body?.attemptId || "").trim();
  const attempt = signInAttempts.get(attemptId);
  if (!attempt)
    return res.status(400).json({
      ok: false,
      error: "Sign-in attempt expired. Please sign in again.",
    });
  if (Date.now() > attempt.expiresAt) {
    signInAttempts.delete(attemptId);
    return res.status(400).json({
      ok: false,
      error: "Sign-in attempt expired. Please sign in again.",
    });
  }

  if (attempt.method !== "email") {
    return res.status(400).json({
      ok: false,
      error:
        attempt.method === "totp"
          ? "Authenticator 2FA is enabled. No email code is required."
          : "Backup codes are enabled. No email code is required.",
    });
  }

  try {
    const result = await sendOtpEmail({
      email: attempt.email,
      purpose: `signin:${attemptId}`,
      req,
    });
    return res.status(result.status).json(result.payload);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to send.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/signin/complete", (req, res) => {
  const attemptId = String(req.body?.attemptId || "").trim();
  const code = String(req.body?.code || "").trim();
  const attempt = signInAttempts.get(attemptId);
  if (!attempt)
    return res.status(400).json({
      ok: false,
      error: "Sign-in attempt expired. Please sign in again.",
    });
  if (Date.now() > attempt.expiresAt) {
    signInAttempts.delete(attemptId);
    return res.status(400).json({
      ok: false,
      error: "Sign-in attempt expired. Please sign in again.",
    });
  }

  const email = attempt.email;
  const users = loadUsers();
  const user = users.find((u) => normalizeEmail(u.email) === email);
  if (!user)
    return res.status(401).json({ ok: false, error: "User not found." });

  if (attempt.method === "backup") {
    const consumed = consumeBackupCode(user, code);
    if (!consumed)
      return res.status(400).json({
        ok: false,
        error: "Invalid backup code.",
      });
    saveUsers(users);
  } else if (attempt.method === "email") {
    if (/^\d{4}$/.test(code)) {
      const key = otpKey({ email, purpose: `signin:${attemptId}` });
      const entry = otpStore.get(key);
      if (!entry)
        return res
          .status(400)
          .json({ ok: false, error: "Please send a code first." });
      if (Date.now() > entry.expiresAt) {
        otpStore.delete(key);
        return res
          .status(400)
          .json({ ok: false, error: "Code expired. Please resend." });
      }
      if (sha256(code) !== entry.codeHash) {
        entry.attempts += 1;
        otpStore.set(key, entry);
        return res.status(400).json({ ok: false, error: "Incorrect code." });
      }
      otpStore.delete(key);
    } else {
      // Allow backup code as a sign-in fallback when 2FA is required.
      const consumed = consumeBackupCode(user, code);
      if (!consumed)
        return res.status(400).json({ ok: false, error: "Invalid code." });
      saveUsers(users);
    }
  } else {
    if (/^\d{6}$/.test(code)) {
      const secret = String(user.totpSecret || "");
      if (!secret)
        return res
          .status(400)
          .json({ ok: false, error: "Authenticator is not set up." });
      if (!verifyTotp({ secret, code })) {
        return res.status(400).json({
          ok: false,
          error: "Invalid or expired authenticator code.",
        });
      }
    } else {
      // Allow backup code as a fallback for TOTP sign-in.
      const consumed = consumeBackupCode(user, code);
      if (!consumed)
        return res
          .status(400)
          .json({ ok: false, error: "Invalid authenticator code." });
      saveUsers(users);
    }
  }

  signInAttempts.delete(attemptId);

  const sid = crypto.randomUUID?.() || crypto.randomBytes(16).toString("hex");
  sessions.set(sid, { email, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
  setCookie(res, "sid", sid, { maxAgeSeconds: 24 * 60 * 60 });
  return res.json({
    ok: true,
    user: {
      username: user.username,
      phone: user.phone,
      email: user.email,
      uniqueUsername: user.uniqueUsername,
      twoFactorEnabled: !!user.twoFactorEnabled,
      twoFactorMode: getTwoFactorMode(user),
      hasTotpSecret: !!String(user.totpSecret || ""),
      backupCodesRemaining: backupCodesRemaining(user),
      backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
    },
  });
});

app.get("/api/me", requireAuth, (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => normalizeEmail(u.email) === req.authEmail);
  if (!user)
    return res.status(401).json({ ok: false, error: "Not signed in." });
  const twoFactorMode = getTwoFactorMode(user);
  return res.json({
    ok: true,
    user: {
      username: user.username,
      phone: user.phone,
      email: user.email,
      uniqueUsername: user.uniqueUsername,
      twoFactorEnabled: !!user.twoFactorEnabled,
      twoFactorMode,
      hasTotpSecret: !!String(user.totpSecret || ""),
      backupCodesRemaining: backupCodesRemaining(user),
      backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
    },
  });
});

app.post("/api/account/update", requireAuth, (req, res) => {
  try {
    const users = loadUsers();
    const idx = users.findIndex(
      (u) => normalizeEmail(u.email) === req.authEmail
    );
    if (idx === -1)
      return res.status(401).json({ ok: false, error: "Not signed in." });

    const user = users[idx];
    const nextUsername =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "username")
        ? String(req.body.username || "").trim()
        : null;
    const nextUnique =
      req.body &&
      Object.prototype.hasOwnProperty.call(req.body, "uniqueUsername")
        ? String(req.body.uniqueUsername || "").trim()
        : null;
    const nextPhone =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "phone")
        ? String(req.body.phone || "").trim()
        : null;
    const nextEmailRaw =
      req.body && Object.prototype.hasOwnProperty.call(req.body, "email")
        ? String(req.body.email || "")
        : null;

    if (nextUsername != null) {
      if (!nextUsername)
        return res
          .status(400)
          .json({ ok: false, error: "UserName is required." });
      if (nextUsername.length > 60)
        return res
          .status(400)
          .json({ ok: false, error: "UserName is too long." });
      user.username = nextUsername;
    }

    if (nextUnique != null) {
      if (!nextUnique)
        return res
          .status(400)
          .json({ ok: false, error: "Unique UserName is required." });
      const normalizedUnique = nextUnique.toLowerCase();
      if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(normalizedUnique)) {
        return res.status(400).json({
          ok: false,
          error:
            "Unique UserName must use lowercase letters, numbers, and hyphens only.",
        });
      }
      const taken = users.some(
        (u) =>
          u !== user &&
          String(u.uniqueUsername || "").toLowerCase() === normalizedUnique
      );
      if (taken)
        return res
          .status(409)
          .json({ ok: false, error: "Unique UserName already taken." });
      user.uniqueUsername = normalizedUnique;
    }

    if (nextPhone != null) {
      if (!isValidPhone(nextPhone))
        return res
          .status(400)
          .json({ ok: false, error: "Invalid phone number." });
      user.phone = nextPhone;
    }

    let emailChanged = false;
    let newEmail = null;
    if (nextEmailRaw != null) {
      newEmail = normalizeEmail(nextEmailRaw);
      if (!isValidEmail(newEmail))
        return res.status(400).json({ ok: false, error: "Invalid email." });
      if (normalizeEmail(user.email) !== newEmail) {
        const taken = users.some((u) => normalizeEmail(u.email) === newEmail);
        if (taken)
          return res
            .status(409)
            .json({ ok: false, error: "Email already registered." });
        const oldEmail = normalizeEmail(user.email);
        user.email = newEmail;
        emailChanged = true;

        // Keep this session pointed at the new email.
        const session = req.authSid ? sessions.get(req.authSid) : null;
        if (session) session.email = newEmail;

        // Move any pending TOTP setup keyed by email.
        const pending = pendingTotpSetups.get(oldEmail);
        if (pending) {
          pendingTotpSetups.delete(oldEmail);
          pendingTotpSetups.set(newEmail, pending);
        }

        // Clear stale OTP entries & send-state tied to the old email.
        for (const k of Array.from(otpStore.keys())) {
          if (String(k).endsWith(`:${oldEmail}`)) otpStore.delete(k);
        }
        const sendState = emailSendState.get(oldEmail);
        if (sendState) {
          emailSendState.delete(oldEmail);
          emailSendState.set(newEmail, sendState);
        }
      }
    }

    saveUsers(users);
    const twoFactorMode = getTwoFactorMode(user);
    return res.json({
      ok: true,
      emailChanged,
      user: {
        username: user.username,
        phone: user.phone,
        email: user.email,
        uniqueUsername: user.uniqueUsername,
        twoFactorEnabled: !!user.twoFactorEnabled,
        twoFactorMode,
        hasTotpSecret: !!String(user.totpSecret || ""),
        backupCodesRemaining: backupCodesRemaining(user),
        backupCodesCreatedAt: String(user.backupCodes?.createdAt || ""),
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Update failed.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/account/password", requireAuth, (req, res) => {
  try {
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");
    if (!currentPassword)
      return res
        .status(400)
        .json({ ok: false, error: "Current password is required." });
    if (!newPassword || newPassword.length < 6)
      return res.status(400).json({
        ok: false,
        error: "New password must be at least 6 characters.",
      });

    const users = loadUsers();
    const idx = users.findIndex(
      (u) => normalizeEmail(u.email) === req.authEmail
    );
    if (idx === -1)
      return res.status(401).json({ ok: false, error: "Not signed in." });

    const user = users[idx];
    if (user.passwordHash !== sha256(currentPassword)) {
      return res
        .status(401)
        .json({ ok: false, error: "Current password is incorrect." });
    }

    user.passwordHash = sha256(newPassword);
    saveUsers(users);
    return res.json({ ok: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Update failed.";
    return res.status(500).json({ ok: false, error: message });
  }
});

app.post("/api/backup-codes/enable", requireAuth, (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  const codes = Array.from({ length: BACKUP_CODES_COUNT }, generateBackupCode);
  setBackupCodes(users[idx], codes);
  saveUsers(users);

  return res.json({
    ok: true,
    remaining: codes.length,
    createdAt: String(users[idx].backupCodes?.createdAt || ""),
    codes,
  });
});

app.post("/api/backup-codes/disable", requireAuth, (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  clearBackupCodes(users[idx]);
  saveUsers(users);
  return res.json({ ok: true });
});

app.get("/api/backup-codes/status", requireAuth, (req, res) => {
  const users = loadUsers();
  const user = users.find((u) => normalizeEmail(u.email) === req.authEmail);
  if (!user)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  return res.json({
    ok: true,
    remaining: backupCodesRemaining(user),
    createdAt: String(user.backupCodes?.createdAt || ""),
  });
});

app.post("/api/2fa/set", requireAuth, (req, res) => {
  const enabled = !!req.body?.enabled;
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });
  // Backward-compatible endpoint: toggles EMAIL 2FA.
  setTwoFactorMode(users[idx], enabled ? "email" : "none");
  saveUsers(users);
  return res.json({ ok: true, enabled });
});

app.post("/api/2fa/method", requireAuth, (req, res) => {
  const method = String(req.body?.method || "none").toLowerCase();
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  if (method === "totp") {
    const secret = String(users[idx].totpSecret || "");
    if (!secret) {
      return res.status(400).json({
        ok: false,
        error: "Authenticator not set up yet. Use Authenticator setup first.",
      });
    }
  }

  if (!TWO_FACTOR_MODES.has(method)) {
    return res.status(400).json({ ok: false, error: "Invalid 2FA method." });
  }

  setTwoFactorMode(users[idx], method);
  saveUsers(users);
  return res.json({ ok: true, method, enabled: method !== "none" });
});

app.post("/api/totp/begin", requireAuth, (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  const user = users[idx];
  const email = normalizeEmail(user.email);
  const issuer = process.env.TOTP_ISSUER || "Email Varification";
  const qrUrl = `/api/totp/qr?ts=${Date.now()}`;

  // If there is a pending setup/reset, return that first (so the QR matches what the user is confirming).
  const pending = pendingTotpSetups.get(email);
  const pendingValid =
    pending && Date.now() - pending.createdAt < PENDING_TOTP_TTL_MS;
  if (pendingValid) {
    const buildResponse = (qrDataUrl) =>
      res.json({
        ok: true,
        pending: true,
        secret: pending.secret,
        otpauthUri: pending.otpauthUri,
        issuer: pending.issuer,
        qrUrl,
        qrDataUrl,
      });

    if (pending.qrDataUrl) return buildResponse(pending.qrDataUrl);
    if (!QRCode) return buildResponse(null);
    QRCode.toDataURL(pending.otpauthUri, { margin: 1, width: 220 })
      .then((dataUrl) => {
        pending.qrDataUrl = dataUrl;
        pendingTotpSetups.set(email, pending);
        buildResponse(dataUrl);
      })
      .catch(() => buildResponse(null));
    return;
  }

  // If already set up, return the existing secret + QR (do not rotate).
  const existingSecret = String(user.totpSecret || "");
  if (existingSecret) {
    const otpauthUri = buildTotpOtpauthUri({
      issuer,
      email: user.email,
      secret: existingSecret,
    });

    const buildResponse = (qrDataUrl) =>
      res.json({
        ok: true,
        alreadySetup: true,
        secret: existingSecret,
        otpauthUri,
        issuer,
        qrUrl,
        qrDataUrl,
      });

    if (!QRCode) return buildResponse(null);
    QRCode.toDataURL(otpauthUri, { margin: 1, width: 220 })
      .then((dataUrl) => buildResponse(dataUrl))
      .catch(() => buildResponse(null));
    return;
  }

  const payload = getOrCreatePendingTotpSetup({ email, issuer });
  const { secret, otpauthUri } = payload;

  const buildResponse = (qrDataUrl) =>
    res.json({ ok: true, secret, otpauthUri, issuer, qrUrl, qrDataUrl });

  if (!QRCode) {
    // Client can still do manual setup with the Base32 secret.
    return buildResponse(null);
  }

  QRCode.toDataURL(otpauthUri, { margin: 1, width: 220 })
    .then((dataUrl) => {
      payload.qrDataUrl = dataUrl;
      pendingTotpSetups.set(email, payload);
      buildResponse(dataUrl);
    })
    .catch(() => buildResponse(null));
});

app.post("/api/totp/reset-begin", requireAuth, (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  const user = users[idx];
  const email = normalizeEmail(user.email);
  const issuer = process.env.TOTP_ISSUER || "Email Varification";
  const qrUrl = `/api/totp/qr?ts=${Date.now()}`;

  // IMPORTANT: do not delete the existing secret yet.
  // We only rotate to the new secret after /api/totp/confirm succeeds.
  const payload = getOrCreatePendingTotpSetup({
    email,
    issuer,
    forceNew: true,
  });

  const buildResponse = (qrDataUrl) =>
    res.json({
      ok: true,
      reset: true,
      secret: payload.secret,
      otpauthUri: payload.otpauthUri,
      issuer: payload.issuer,
      qrUrl,
      qrDataUrl,
    });

  if (payload.qrDataUrl) return buildResponse(payload.qrDataUrl);
  if (!QRCode) return buildResponse(null);
  QRCode.toDataURL(payload.otpauthUri, { margin: 1, width: 220 })
    .then((dataUrl) => {
      payload.qrDataUrl = dataUrl;
      pendingTotpSetups.set(email, payload);
      buildResponse(dataUrl);
    })
    .catch(() => buildResponse(null));
});

app.get("/api/totp/qr", requireAuth, async (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  if (!QRCode) {
    return res
      .status(501)
      .json({ ok: false, error: "QR generation is not available." });
  }

  const user = users[idx];
  const email = normalizeEmail(user.email);
  const issuer = process.env.TOTP_ISSUER || "Email Varification";

  // Prefer pending setup/reset if present, even if an existing secret exists.
  const pending = pendingTotpSetups.get(email);
  const pendingValid =
    pending && Date.now() - pending.createdAt < PENDING_TOTP_TTL_MS;
  const existingSecret = String(user.totpSecret || "");

  const setup = pendingValid
    ? pending
    : existingSecret
    ? {
        secret: existingSecret,
        issuer,
        otpauthUri: buildTotpOtpauthUri({
          issuer,
          email,
          secret: existingSecret,
        }),
      }
    : getOrCreatePendingTotpSetup({ email, issuer });

  try {
    const pngBuffer = await QRCode.toBuffer(setup.otpauthUri, {
      type: "png",
      width: 220,
      margin: 1,
    });
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(pngBuffer);
  } catch {
    return res
      .status(500)
      .json({ ok: false, error: "Failed to generate QR code." });
  }
});

app.post("/api/totp/cancel", requireAuth, (req, res) => {
  const email = normalizeEmail(req.authEmail);
  pendingTotpSetups.delete(email);
  return res.json({ ok: true });
});

app.post("/api/totp/confirm", requireAuth, (req, res) => {
  const code = String(req.body?.code || "").trim();
  if (!/^\d{6}$/.test(code)) {
    return res
      .status(400)
      .json({ ok: false, error: "Enter the 6-digit authenticator code." });
  }

  const users = loadUsers();
  const idx = users.findIndex((u) => normalizeEmail(u.email) === req.authEmail);
  if (idx === -1)
    return res.status(401).json({ ok: false, error: "Not signed in." });

  const user = users[idx];

  const email = normalizeEmail(user.email);
  const pending = pendingTotpSetups.get(email);
  const pendingValid =
    pending && Date.now() - pending.createdAt < PENDING_TOTP_TTL_MS;

  // Prefer confirming a pending setup (new secret not yet saved).
  if (pendingValid) {
    if (!verifyTotp({ secret: pending.secret, code })) {
      return res
        .status(400)
        .json({ ok: false, error: "Invalid or expired authenticator code." });
    }
    user.totpSecret = pending.secret;
    pendingTotpSetups.delete(email);
    setTwoFactorMode(user, "totp");
    saveUsers(users);
    return res.json({ ok: true, method: "totp" });
  }

  // If a secret already exists, allow confirmation to enable TOTP without showing QR again.
  const existingSecret = String(user.totpSecret || "");
  if (!existingSecret) {
    return res
      .status(400)
      .json({ ok: false, error: "Authenticator setup not started yet." });
  }
  if (!verifyTotp({ secret: existingSecret, code })) {
    return res
      .status(400)
      .json({ ok: false, error: "Invalid or expired authenticator code." });
  }

  setTwoFactorMode(user, "totp");
  saveUsers(users);
  return res.json({ ok: true, method: "totp" });
});

app.post("/api/signout", (req, res) => {
  const cookies = cookieParse(req.headers.cookie);
  const sid = cookies.sid;
  if (sid) sessions.delete(sid);
  clearCookie(res, "sid");
  return res.json({ ok: true });
});

app.get("/api/users/by-unique/:unique", requireAuth, (req, res) => {
  const u = String(req.params.unique || "").toLowerCase();
  const users = loadUsers();
  const user = users.find(
    (x) => String(x.uniqueUsername || "").toLowerCase() === u
  );
  if (!user)
    return res.status(404).json({ ok: false, error: "User not found." });
  return res.json({
    ok: true,
    user: {
      username: user.username,
      uniqueUsername: user.uniqueUsername,
      email: user.email,
    },
  });
});

// SPA-ish: ensure index.html is served
app.get("/", (_req, res) => {
  res.sendFile(path.join(ROOT, "index.html"));
});

// API-only 404 (keeps responses consistent for frontend fetch())
app.use("/api", (_req, res) => {
  return res.status(404).json({ ok: false, error: "API route not found." });
});

// API-only error handler (prevents HTML error responses for fetch())
app.use((err, req, res, next) => {
  if (!String(req.path || "").startsWith("/api")) return next(err);
  const message = err instanceof Error ? err.message : "Internal server error.";
  console.error("API error:", message);
  return res.status(500).json({ ok: false, error: "Internal server error." });
});

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log("Open that URL (don’t open index.html directly).");
});

server.on("error", (err) => {
  if (err && err.code === "EADDRINUSE") {
    const suggestedPort = port + 1;
    console.error(`Port ${port} is already in use.`);
    console.error("Set a different port and retry:");
    console.error(`  $env:PORT=${suggestedPort}; npm start`);
    process.exit(1);
  }
  throw err;
});
