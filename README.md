# Juice Shop Login Clone (Secure)

A small login form that mimics the look of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)'s login page, built to demonstrate **defensive** web-security practices for a class assignment (HW 2B).

The focus is not the UI — it's showing how to validate input on **both** the client and the server, and how to handle passwords and SQL safely so that common attacks (SQL injection, XSS, authentication bypass, brute force) do not work.

## What it does

- Renders an email + password login form (`public/index.html`).
- **Client-side validation** (`public/app.js`): blocks empty submissions, requires `@` in the email, and requires a password of at least 8 characters — before any request is sent.
- **Server-side validation** (`server.js`): re-runs the same checks on every request, because client checks can be bypassed with curl/DevTools.
- Authenticates against an in-memory SQLite database using:
  - **Parameterized queries** → SQL injection payloads are treated as literal data.
  - **bcrypt** password hashing (cost 12) → no plaintext passwords stored or compared.
  - **Generic error messages** → the server never says whether the email or the password was wrong (prevents account enumeration).
  - **Rate limiting** → 10 attempts per IP per 15 minutes (slows brute force / credential stuffing).
- Status messages are written with `textContent`, never `innerHTML`, so echoed input can never execute as script (XSS defense).

## Demo credentials

| Email | Password |
|-------|----------|
| `admin@juice-sh.op` | `CorrectHorseBatteryStaple` |

## How to run

**Prerequisites:** Node.js 18+ and npm.

```bash
npm install
npm start
```

Then open <http://localhost:3000> in your browser.

## Project structure

```
.
├── public/
│   ├── index.html   # login form markup
│   ├── styles.css   # styling
│   └── app.js       # client-side validation + fetch to the API
├── server.js        # Express API: validation, bcrypt, parameterized SQL, rate limiting
├── package.json
└── README.md
```

## Security notes

This project is intentionally built the *secure* way. For the assignment's Part 3, `WRITEUP.md` also shows the **insecure** code pattern an attacker could exploit (string-concatenated SQL) and confirms that the parameterized version here defeats the same payload.

> ⚠️ This is a teaching demo. Do not use the in-memory DB or the demo credentials in production.
