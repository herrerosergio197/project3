const path = require("path");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");

const app = express();

app.use(express.json());
// This file now lives in /public, so static root is the same directory.
app.use(express.static(__dirname));

// Comments are stored in MySQL so they persist across restarts.
// Configure via env vars:
// MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE
let mysqlPool = null;
let mysqlReady = false;

async function initMySql() {
  const host = process.env.MYSQL_HOST || "127.0.0.1";
  const port = process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306;
  const user = process.env.MYSQL_USER || "root";
  const password = process.env.MYSQL_PASSWORD || "";
  const database = process.env.MYSQL_DATABASE || "blog";

  mysqlPool = mysql.createPool({
    host,
    port,
    user,
    password,
    database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: "Z",
  });

  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS comments (
      id VARCHAR(36) NOT NULL PRIMARY KEY,
      article_id VARCHAR(64) NOT NULL,
      name VARCHAR(60) NOT NULL,
      text TEXT NOT NULL,
      created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      INDEX idx_comments_article_created (article_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
  mysqlReady = true;
}

function requireMySql(res) {
  if (mysqlPool && mysqlReady) return true;
  res.status(503).json({
    ok: false,
    error:
      "Comments database is not configured. Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE and restart the server.",
  });
  return false;
}

// Demo users (replace with DB if you want)
const USERS = [
  {
    username: "zadmin",
    displayName: "Admin",
    role: "reader",
    passwordHash: "$2b$10$qL7/uaxoD9IvB3lGse5np.gXBNJiXuWqAMemOQ4rTrFVuplhCJa5q", // pass.txt
  },
];

// Very small in-memory session store (good enough for demo; use Redis/DB for real apps)
const SESSIONS = new Map(); // token -> { username, displayName, role, createdAt }
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h

function createToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function safeUserSession(user) {
  return { username: user.username, displayName: user.displayName, role: user.role };
}

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of SESSIONS.entries()) {
    if (!session?.createdAt || now - session.createdAt > SESSION_TTL_MS) SESSIONS.delete(token);
  }
}

function getSessionFromRequest(req) {
  const auth = req.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  cleanExpiredSessions();
  return SESSIONS.get(m[1]) || null;
}

function normalizeArticleId(id) {
  if (typeof id !== "string") return null;
  const trimmed = id.trim();
  if (!trimmed) return null;
  // Keep it simple: allow letters, numbers, dash/underscore only
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) return null;
  return trimmed;
}

function clampString(s, maxLen) {
  if (typeof s !== "string") return "";
  return s.trim().slice(0, maxLen);
}

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ ok: false, error: "Bad request" });
  }

  const user = USERS.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ ok: false, error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ ok: false, error: "Invalid credentials" });

  const token = createToken();
  SESSIONS.set(token, { ...safeUserSession(user), createdAt: Date.now() });

  return res.json({ ok: true, token, user: safeUserSession(user) });
});

app.post("/api/logout", (req, res) => {
  const auth = req.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) SESSIONS.delete(m[1]);
  return res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) return res.status(401).json({ ok: false, error: "Not authenticated" });
  return res.json({ ok: true, user: safeUserSession(session) });
});

app.get("/api/private/articles", (req, res) => {
  const session = getSessionFromRequest(req);
  if (!session) return res.status(401).json({ ok: false, error: "Not authenticated" });

  return res.json({
    ok: true,
    articles: [
      {
        id: "members-1",
        title: "Internal notes: blog roadmap",
        date: "2026-05-01",
        excerpt:
          "This article is only shown to authenticated users. Ideas: search, tags, editor workflow, and comments.",
      },
      {
        id: "members-2",
        title: "Quick guide for editors",
        date: "2026-05-01",
        excerpt:
          "Recommendations to keep consistency: clear titles, useful links, and a solid subheading structure.",
      },
    ],
  });
});

app.get("/api/articles/:id/comments", (req, res) => {
  const articleId = normalizeArticleId(req.params.id);
  if (!articleId) return res.status(400).json({ ok: false, error: "Bad article id" });
  if (!requireMySql(res)) return;

  mysqlPool
    .query(
      `
      SELECT id, name, text, created_at
      FROM comments
      WHERE article_id = ?
      ORDER BY created_at ASC
    `,
      [articleId]
    )
    .then(([rows]) => {
      const comments = (rows || []).map((r) => ({
        id: r.id,
        name: r.name,
        text: r.text,
        createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : new Date(r.created_at).toISOString(),
      }));
      res.json({ ok: true, comments });
    })
    .catch((err) => {
      res.status(500).json({ ok: false, error: err?.message || "DB error" });
    });
});

app.post("/api/articles/:id/comments", (req, res) => {
  const articleId = normalizeArticleId(req.params.id);
  if (!articleId) return res.status(400).json({ ok: false, error: "Bad article id" });
  if (!requireMySql(res)) return;

  const name = clampString(req.body?.name ?? "", 60) || "Anonymous";
  const text = clampString(req.body?.text ?? "", 2000);
  if (!text) return res.status(400).json({ ok: false, error: "Comment text is required" });

  const comment = {
    id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex"),
    name,
    text,
    createdAt: new Date().toISOString(),
  };

  mysqlPool
    .query(
      `
      INSERT INTO comments (id, article_id, name, text, created_at)
      VALUES (?, ?, ?, ?, ?)
    `,
      [comment.id, articleId, comment.name, comment.text, new Date(comment.createdAt)]
    )
    .then(() => res.status(201).json({ ok: true, comment }))
    .catch((err) => res.status(500).json({ ok: false, error: err?.message || "DB error" }));
});

const port = process.env.PORT ? Number(process.env.PORT) : 3000;
initMySql()
  .then(() => {
    app.listen(port, () => {
      // eslint-disable-next-line no-console
      console.log(`Blog running on http://localhost:${port}`);
      // eslint-disable-next-line no-console
      console.log("Comments: MySQL enabled");
    });
  })
  .catch((err) => {
    mysqlReady = false;
    mysqlPool = null;
    // eslint-disable-next-line no-console
    console.error("MySQL init failed:", err?.message || err);
    // Start anyway so the UI loads; comment API will return 503 until configured.
    app.listen(port, () => {
      // eslint-disable-next-line no-console
      console.log(`Blog running on http://localhost:${port}`);
      // eslint-disable-next-line no-console
      console.log("Comments: MySQL NOT configured (API returns 503)");
    });
  });