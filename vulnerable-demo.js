// FOR DEMONSTRATION ONLY (assignment Part 3).
// This shows the INSECURE pattern, string-concatenated SQL, and proves the
// same injection payload that FAILS against server.js SUCCEEDS here.
// This file is never imported by the real server.

const initSqlJs = require("sql.js");

const PAYLOAD_EMAIL = "admin@juice-sh.op' OR '1'='1";
const PAYLOAD_PASSWORD = "anything";

initSqlJs().then((SQL) => {
  const db = new SQL.Database();
  db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT);`);
  db.run(`INSERT INTO users (email, password_hash) VALUES ('admin@juice-sh.op', 'real-hash');`);

  // ❌ VULNERABLE: user input concatenated directly into the SQL string.
  const insecureQuery =
    "SELECT * FROM users WHERE email = '" + PAYLOAD_EMAIL + "'";
  console.log("Executed query:\n  " + insecureQuery + "\n");

  const stmt = db.prepare(insecureQuery);
  let rows = 0;
  while (stmt.step()) {
    rows++;
    console.log("Leaked row:", stmt.getAsObject());
  }
  stmt.free();

  console.log(
    `\nRows returned: ${rows}  ->  ` +
      (rows > 0
        ? "AUTH BYPASS SUCCEEDED (the OR '1'='1' made the WHERE always true)."
        : "no rows.")
  );

  // ✅ SECURE equivalent (what server.js does): bind the same input as a param.
  const safe = db.prepare("SELECT * FROM users WHERE email = :email");
  const safeRow = safe.getAsObject({ ":email": PAYLOAD_EMAIL });
  safe.free();
  console.log(
    "\nParameterized version with the SAME payload -> " +
      (safeRow.email ? "matched a row" : "matched NO rows (injection neutralized).")
  );
});
