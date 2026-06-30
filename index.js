/* =====================================================================
   TEACHER PAYROLL — BACKEND  (index.js)
   Node.js + Express + PostgreSQL + bcrypt + JWT
   Same proven recipe as your other app. Deploy on Render, auto-deploy from GitHub.

   ENVIRONMENT VARIABLES to set in Render (Settings → Environment):
     DATABASE_URL   — your Render PostgreSQL connection string
     JWT_SECRET     — any long random string (your choice)
     ADMIN_EMAIL    — the ONE email allowed to be admin (e.g. nathansteyn96@gmail.com)
     LICENSE_SECRET — long random string used to sign licence keys (must match index.html app)
     (later) VNPAY_TMN_CODE, VNPAY_HASH_SECRET — from your VNPay merchant account

   This file creates its own database tables on first run. No manual SQL needed.
   ===================================================================== */

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* ---- config from environment (never hard-code secrets) ---- */
const JWT_SECRET     = process.env.JWT_SECRET     || "dev-only-change-me";
const ADMIN_EMAIL    = (process.env.ADMIN_EMAIL   || "").toLowerCase();
const LICENSE_SECRET = process.env.LICENSE_SECRET || "dev-only-license-secret";
const APP_URL        = process.env.APP_URL        || "https://teacher-payroll.onrender.com";

/* ---- database ---- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("render.com")
        ? { rejectUnauthorized: false } : false
});

/* ---- middleware ---- */
// Helmet adds security headers. We relax the Content Security Policy just enough
// to allow our own pages' inline scripts/styles to run (the app pages use inline JS).
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"]
    }
  }
}));
app.use(cors());
app.use(express.json());
app.use(express.static("public")); // serves the frontend pages from /public
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300 })); // basic abuse limit

/* ---- create tables on startup ---- */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS centres (
      id            SERIAL PRIMARY KEY,
      centre_name   TEXT NOT NULL,
      contact_name  TEXT,
      email         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'centre',   -- 'centre' or 'admin'
      plan          TEXT DEFAULT 'monthly',           -- 'monthly' or 'yearly'
      status        TEXT NOT NULL DEFAULT 'pending_payment', -- pending_payment | active | expired
      paid          BOOLEAN DEFAULT FALSE,
      licence_key   TEXT,
      expiry        TEXT,                              -- YYYYMMDD or '' for no expiry
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log("Database ready.");
}

/* ---- helpers ---- */
function signToken(centre) {
  return jwt.sign(
    { id: centre.id, email: centre.email, role: centre.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// verify the login token on protected routes
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Session expired, please log in again" });
  }
}

// admin-only guard
function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access only" });
  }
  next();
}

// licence key — same format/algorithm as the app's index.html
//   key = base64(payload).signature   payload = {c: centreName, e: expiryYYYYMMDD or ""}
function makeLicenceKey(centreName, expiry) {
  const payload = JSON.stringify({ c: centreName, e: expiry || "" });
  const sig = crypto.createHash("sha256").update(payload + LICENSE_SECRET).digest("hex").slice(0, 16);
  return Buffer.from(payload, "utf8").toString("base64") + "." + sig;
}
function ymdAfterMonths(months) {
  const d = new Date();
  d.setMonth(d.getMonth() + months);
  return "" + (d.getFullYear() * 10000 + (d.getMonth() + 1) * 100 + d.getDate());
}

/* =====================================================================
   AUTH ROUTES
   ===================================================================== */

// register a new centre/school
app.post("/api/register", async (req, res) => {
  try {
    const { centre_name, contact_name, email, password, plan } = req.body;
    if (!centre_name || !email || !password) {
      return res.status(400).json({ error: "Centre name, email and password are required" });
    }
    const emailLc = String(email).toLowerCase().trim();

    // role: admin ONLY for the configured admin email; everyone else is a centre
    const role = emailLc === ADMIN_EMAIL ? "admin" : "centre";

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO centres (centre_name, contact_name, email, password_hash, role, plan, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, centre_name, email, role, status`,
      [centre_name, contact_name || "", emailLc, hash, role,
       plan === "yearly" ? "yearly" : "monthly",
       role === "admin" ? "active" : "pending_payment"]
    );
    const centre = result.rows[0];
    // NOTE (payments): a real centre is 'pending_payment' until VNPay confirms.
    // The VNPay webhook (below, later) flips status to 'active' and issues the key.
    return res.json({ ok: true, centre });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That email is already registered" });
    console.error(e);
    return res.status(500).json({ error: "Registration failed" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const emailLc = String(email || "").toLowerCase().trim();
    const result = await pool.query("SELECT * FROM centres WHERE email=$1", [emailLc]);
    const centre = result.rows[0];
    if (!centre) return res.status(401).json({ error: "Wrong email or password" });
    const ok = await bcrypt.compare(password || "", centre.password_hash);
    if (!ok) return res.status(401).json({ error: "Wrong email or password" });

    const token = signToken(centre);
    return res.json({
      ok: true,
      token,
      role: centre.role,
      status: centre.status,
      centre_name: centre.centre_name,
      licence_key: centre.licence_key || null
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Login failed" });
  }
});

// who am I (used by frontend to check session)
app.get("/api/me", authenticate, async (req, res) => {
  const result = await pool.query(
    "SELECT id, centre_name, email, role, status, plan, paid, expiry, licence_key FROM centres WHERE id=$1",
    [req.user.id]
  );
  return res.json({ ok: true, centre: result.rows[0] || null });
});

/* =====================================================================
   ADMIN ROUTES  (only the admin email can use these)
   ===================================================================== */

// list every centre — this is what fills your admin dashboard
app.get("/api/admin/centres", authenticate, adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT id, centre_name, email, role, plan, status, paid, expiry, created_at
     FROM centres WHERE role <> 'admin' ORDER BY created_at DESC`
  );
  return res.json({ ok: true, centres: result.rows });
});

// issue / renew a licence key for a centre and mark active
app.post("/api/admin/issue-key", authenticate, adminOnly, async (req, res) => {
  try {
    const { centre_id, months } = req.body; // months: number, or 0 for no expiry
    const r = await pool.query("SELECT * FROM centres WHERE id=$1", [centre_id]);
    const centre = r.rows[0];
    if (!centre) return res.status(404).json({ error: "Centre not found" });

    const m = parseInt(months);
    const expiry = (m && m > 0) ? ymdAfterMonths(m) : "";
    const key = makeLicenceKey(centre.centre_name, expiry);

    await pool.query(
      "UPDATE centres SET licence_key=$1, expiry=$2, status='active', paid=TRUE WHERE id=$3",
      [key, expiry, centre_id]
    );
    return res.json({ ok: true, licence_key: key, expiry });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Could not issue key" });
  }
});

// mark a centre inactive (does not delete their device data — just ends server access)
app.post("/api/admin/mark-inactive", authenticate, adminOnly, async (req, res) => {
  const { centre_id } = req.body;
  await pool.query("UPDATE centres SET status='expired', paid=FALSE WHERE id=$1", [centre_id]);
  return res.json({ ok: true });
});

/* =====================================================================
   PAYMENTS — VNPay  (LATER STEP, needs your merchant account + live testing)
   ---------------------------------------------------------------------
   When you have VNPay credentials, this is where it plugs in:
     1) POST /api/pay/create  → builds a VNPay payment URL for the chosen plan,
        sends the centre to VNPay to pay.
     2) GET  /api/pay/return  → VNPay redirects back here after payment.
     3) POST /api/pay/ipn     → VNPay's server calls this to CONFIRM payment.
        The confirmation MUST be verified with your VNPAY_HASH_SECRET (signature check).
        On a verified success: set status='active', paid=TRUE, generate the licence key,
        and email it to the centre — fully automatic, no action from you.

   This signature verification is security-critical and must be tested against
   VNPay's real system with your real keys before going live. Left as a marked
   stub so a developer (or you, carefully) completes it with your credentials.
   ===================================================================== */
app.post("/api/pay/create", authenticate, (req, res) => {
  return res.status(501).json({
    error: "VNPay not configured yet",
    note: "Add VNPAY_TMN_CODE and VNPAY_HASH_SECRET, then complete the VNPay section in index.js."
  });
});

/* ---- health check ---- */
app.get("/api/health", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ---- start ---- */
if (require.main === module) {
  initDb()
    .then(() => app.listen(PORT, () => console.log("Teacher Payroll backend running on port " + PORT)))
    .catch(err => { console.error("Failed to start:", err); process.exit(1); });
}

module.exports = { app, pool, initDb, makeLicenceKey };
