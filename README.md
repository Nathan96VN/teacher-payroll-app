# Teacher Payroll — Backend

This is the server for the Teacher Payroll SaaS. Same recipe as your other app:
**Node + Express + PostgreSQL on Render, auto-deploy from GitHub.**

It gives you: school accounts, login, admin role, an admin list of all schools,
and licence-key issuing. Payroll data still lives encrypted on each school's device —
the server only holds accounts (low data risk). VNPay payments are a marked later step.

---

## What's in here

- `index.js` — the whole backend (register, login, roles, admin list, issue key).
- `package.json` — the dependencies (Express, pg, bcryptjs, jsonwebtoken, etc.).
- `public/` — the web pages the server serves:
  - `index.html` — the payroll app (licence gate + encrypted saving)
  - `landing.html` — the marketing page
  - `auth.html` — register / login (talks to this backend)
  - `admin-dashboard.html` — your admin dashboard (talks to this backend)

---

## How to deploy (browser only — same as your other app)

### 1. New GitHub repo
Create a NEW repository (e.g. `teacher-payroll-app`). Upload everything in this folder
(`index.js`, `package.json`, and the `public/` folder with its files).

### 2. New PostgreSQL database on Render
- Render Dashboard → New → PostgreSQL. Free tier is fine to start.
- When it's created, copy its **Internal Database URL**.

### 3. New Web Service on Render
- Render Dashboard → New → Web Service → connect the new GitHub repo.
- Build Command: `npm install`
- Start Command: `npm start`
- Instance type: Free to start.

### 4. Environment variables (Render → your Web Service → Environment)
Add these (this is where secrets live — never in code):

| Key | Value |
|-----|-------|
| `DATABASE_URL` | the database URL from step 2 |
| `JWT_SECRET` | any long random string you make up |
| `ADMIN_EMAIL` | `nathansteyn96@gmail.com` (the ONLY email that becomes admin) |
| `LICENSE_SECRET` | must match `LICENSE_SECRET` in `public/index.html` |
| `APP_URL` | your live app URL, e.g. `https://your-service.onrender.com` |

> **Important:** `LICENSE_SECRET` here must be IDENTICAL to the one in
> `public/index.html`, or the keys you issue won't unlock the app.

### 5. Deploy
Render auto-deploys when you push to `main`. The database tables are created
automatically on first start — no manual SQL.

---

## How it works once live

1. A school opens `/auth.html`, registers (saved as `pending_payment`).
2. You log in at `/auth.html` with your admin email → lands on `/admin-dashboard.html`.
3. You see every school. Click **Send key** → it issues a real key, marks them
   active, and opens a pre-filled email with the key.
4. The school enters their email + key on `/index.html` to unlock the app.
5. Their payroll data saves encrypted on their own device.

**You become admin** by registering once with the `ADMIN_EMAIL` address.

---

## Adding VNPay later (automatic payments)

In `index.js` see the section marked `PAYMENTS — VNPay`. When you have a VNPay
merchant account:
- Add `VNPAY_TMN_CODE` and `VNPAY_HASH_SECRET` as environment variables.
- Complete the three marked routes (`/api/pay/create`, `/api/pay/return`, `/api/pay/ipn`).
- The payment confirmation (`/api/pay/ipn`) MUST verify VNPay's signature with your
  hash secret — this is security-critical and must be tested against VNPay's real
  system before going live.

Once done, paying automatically flips a school to active and emails their key —
no action from you.

---

## Notes

- Passwords are hashed with bcryptjs (never stored in plain text).
- Login uses a 7-day JWT token (standard "stay logged in" mechanism).
- Only `ADMIN_EMAIL` can reach the admin routes; everyone else is blocked (403).
- Free tier "sleeps" when idle (first request is slow ~50s) — upgrade to paid for always-on.
