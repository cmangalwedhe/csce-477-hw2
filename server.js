// Minimal Express server demonstrating SECURE login handling:
//  - server-side re-validation (never trust the client)
//  - parameterized SQL queries (prevents SQL injection)
//  - bcrypt password hashing (never store or compare plaintext)
//  - generic error messages (prevents account enumeration)
//  - a rate limiter (slows brute-force / credential stuffing)
//
// Uses pure-JS dependencies (bcryptjs + sql.js) so it runs anywhere with
// no native compiler toolchain required.

const express = require("express");
const bcrypt = require("bcryptjs");
const initSqlJs = require("sql.js");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static("public"));

// --- Validation --------------------------------------------------------------
function validate(email, password) {
  if (typeof email !== "string" || typeof password !== "string") {
    return "Invalid input.";
  }
  if (!email.includes("@")) return "Email must contain '@'.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null;
}

// --- Rate limiting -----------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many attempts. Try again later." },
});

// --- Bootstrap: build an in-memory SQLite DB, then start the server ----------
const SEED_EMAIL = "admin@juice-sh.op";
const SEED_PASSWORD = "CorrectHorseBatteryStaple";

initSqlJs().then((SQL) => {
  const db = new SQL.Database();
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  // Password is hashed with bcrypt (cost 12). Plaintext never hits the DB.
  const seedHash = bcrypt.hashSync(SEED_PASSWORD, 12);
  db.run("INSERT INTO users (email, password_hash) VALUES (?, ?)", [
    SEED_EMAIL,
    seedHash,
  ]);

  // --- Login route -----------------------------------------------------------
  app.post("/api/login", loginLimiter, (req, res) => {
    const { email, password } = req.body || {};

    const error = validate(email, password);
    if (error) {
      return res.status(400).json({ success: false, message: error });
    }

    // Parameterized query: user input is bound as data, so a payload like
    //   ' OR 1=1--
    // is treated as a literal email string and simply matches no rows.
    const stmt = db.prepare("SELECT password_hash FROM users WHERE email = :email");
    const row = stmt.getAsObject({ ":email": email });
    stmt.free();

    const storedHash = row.password_hash;

    // Always run a bcrypt compare (even when no user matched) so response
    // timing does not leak which emails are registered.
    const seedHashFallback = seedHash;
    const match = bcrypt.compareSync(password, storedHash || seedHashFallback);

    if (storedHash && match) {
      return res.json({ success: true, message: "Login successful." });
    }

    // Same generic message whether the email is unknown or the password wrong.
    return res
      .status(401)
      .json({ success: false, message: "Invalid email or password." });
  });

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
});
