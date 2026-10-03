// Client-side validation. This is a convenience layer only, the server
// re-validates everything, because client-side checks can be bypassed.

const form = document.getElementById("loginForm");
const emailEl = document.getElementById("email");
const passwordEl = document.getElementById("password");
const statusEl = document.getElementById("status");

function setStatus(message, kind) {
  // textContent (not innerHTML) ensures any characters the server echoes
  // back are rendered as text, never executed as HTML/JS.
  statusEl.textContent = message;
  statusEl.className = kind || "";
}

function validate(email, password) {
  if (!email || !password) return "Please fill in both fields.";
  if (!email.includes("@")) return "Email must contain '@'.";
  if (password.length < 8) return "Password must be at least 8 characters.";
  return null;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = emailEl.value.trim();
  const password = passwordEl.value;

  const error = validate(email, password);
  if (error) {
    setStatus(error, "error");
    return;
  }

  setStatus("Checking…", "");

  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await res.json();

    if (res.ok && data.success) {
      setStatus("Login successful. Welcome!", "ok");
    } else {
      // Generic message, we never reveal whether the email or the
      // password was the wrong part (prevents account enumeration).
      setStatus(data.message || "Invalid email or password.", "error");
    }
  } catch (err) {
    setStatus("Network error. Please try again.", "error");
  }
});
