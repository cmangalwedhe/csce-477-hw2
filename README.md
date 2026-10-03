# CSCE 477H HW2B: Juice Shop Login Clone

A small login form that mimics the look of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)'s login page. I built it for a web security assignment to practice validating input on both the client and the server, and to handle passwords and SQL in a way that common attacks (SQL injection, XSS, auth bypass, brute force) do not work.

The point of the project is the security, not the UI.

## What it does

* Shows an email and password login form (`public/index.html`).
* Client-side validation (`public/app.js`): blocks empty submissions, requires an `@` in the email, and requires a password of at least 8 characters before anything is sent.
* Server-side validation (`server.js`): runs the same checks again on every request, because client-side checks can be skipped with curl or the dev tools.
* Checks credentials against an in-memory SQLite database using:
  * Parameterized queries, so SQL injection payloads are treated as plain data.
  * bcrypt password hashing (cost 12), so no plaintext passwords are stored or compared.
  * One generic error message, so the server never reveals whether the email or the password was the wrong part.
  * A rate limit of 10 attempts per IP every 15 minutes to slow down brute force.
* Status messages are written with `textContent` instead of `innerHTML`, so anything echoed back shows up as text and cannot run as script.

## Demo credentials

| Email | Password |
|-------|----------|
| `admin@juice-sh.op` | `CorrectHorseBatteryStaple` |

## How to run

You need Node.js 18 or newer and npm.

```bash
npm install
npm start
```

Then open http://localhost:3000 in your browser.

## Files

```
public/
  index.html   login form markup
  styles.css   styling
  app.js        client-side validation and the fetch call
server.js       Express API: validation, bcrypt, parameterized SQL, rate limiting
vulnerable-demo.js   side-by-side demo of concatenated vs parameterized SQL
```

## Note

`vulnerable-demo.js` is there on purpose. It shows the insecure string-concatenated query that an attacker can break, next to the parameterized version that stops the same payload. Run it with `node vulnerable-demo.js`.

This is only a class demo, so do not reuse the in-memory database or the demo password anywhere real.
