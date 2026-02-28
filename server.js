const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-in-production";

const db = new Database(path.join(__dirname, "auth.db"));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);
app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login.html");
  }
  next();
}

app.post("/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({
      error: "Username must be at least 3 chars and password at least 6 chars."
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    );
    const result = insert.run(username, passwordHash);
    req.session.userId = result.lastInsertRowid;
    req.session.username = username;
    return res.json({ ok: true, redirect: "/dashboard" });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "Username already exists." });
    }
    return res.status(500).json({ error: "Server error during registration." });
  }
});

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required." });
  }

  try {
    const user = db
      .prepare("SELECT id, username, password_hash FROM users WHERE username = ?")
      .get(username);
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    return res.json({ ok: true, redirect: "/dashboard" });
  } catch (error) {
    return res.status(500).json({ error: "Server error during login." });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true, redirect: "/login.html" });
  });
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ authenticated: false });
  }
  return res.json({
    authenticated: true,
    user: {
      id: req.session.userId,
      username: req.session.username
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
