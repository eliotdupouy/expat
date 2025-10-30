const express = require('express');
const path = require('path');
const fs = require('fs');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'expat-atlas.db');

let db;

async function initDatabase() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });
  const database = await open({ filename: DB_PATH, driver: sqlite3.Database });
  await database.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS posts (
      id TEXT PRIMARY KEY,
      capital_slug TEXT NOT NULL,
      content TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_posts_capital_created ON posts(capital_slug, created_at DESC);
  `);
  return database;
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function sanitizeForumSlug(raw) {
  const slug = (raw || '').toString().trim().toLowerCase();
  if (!slug || !/^[a-z0-9-]+$/.test(slug)) {
    return null;
  }
  return slug;
}

async function createSession(userId) {
  const token = uuidv4();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 30 * 24 * 60 * 60 * 1000);
  await db.run(
    `INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
    [token, userId, createdAt.toISOString(), expiresAt.toISOString()]
  );
  return { token, createdAt: createdAt.toISOString(), expiresAt: expiresAt.toISOString() };
}

async function getSession(token) {
  return db.get(
    `SELECT sessions.token, sessions.user_id, sessions.expires_at, users.name, users.email, users.created_at
     FROM sessions
     JOIN users ON users.id = sessions.user_id
     WHERE sessions.token = ? AND sessions.expires_at > ?`,
    [token, new Date().toISOString()]
  );
}

function serializeUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    createdAt: row.created_at
  };
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = authHeader.substring('Bearer '.length).trim();
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const session = await getSession(token);
    if (!session) {
      return res.status(401).json({ error: 'Session expired or invalid' });
    }
    req.user = {
      id: session.user_id,
      name: session.name,
      email: session.email,
      createdAt: session.created_at
    };
    req.sessionToken = token;
    next();
  } catch (error) {
    console.error('Failed to validate session', error);
    res.status(500).json({ error: 'Failed to validate session' });
  }
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }
  const normalizedEmail = normalizeEmail(email);
  try {
    const existing = await db.get(`SELECT id FROM users WHERE email = ?`, [normalizedEmail]);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    await db.run(
      `INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
      [id, name.trim(), normalizedEmail, hashed, createdAt]
    );
    const session = await createSession(id);
    res.status(201).json({ user: { id, name: name.trim(), email: normalizedEmail, createdAt }, token: session.token });
  } catch (error) {
    console.error('Failed to register user', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const normalizedEmail = normalizeEmail(email);
  try {
    const user = await db.get(`SELECT id, name, email, password_hash, created_at FROM users WHERE email = ?`, [normalizedEmail]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const session = await createSession(user.id);
    res.json({ user: serializeUser(user), token: session.token });
  } catch (error) {
    console.error('Failed to log in', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    await db.run(`DELETE FROM sessions WHERE token = ?`, [req.sessionToken]);
    res.status(204).end();
  } catch (error) {
    console.error('Failed to log out', error);
    res.status(500).json({ error: 'Failed to log out' });
  }
});

app.get('/api/profile', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/forums/:slug/posts', async (req, res) => {
  const slug = sanitizeForumSlug(req.params.slug);
  if (!slug) {
    return res.status(400).json({ error: 'Invalid forum identifier' });
  }
  try {
    const posts = await db.all(
      `SELECT posts.id, posts.content, posts.created_at, users.name as author_name
       FROM posts
       JOIN users ON users.id = posts.user_id
       WHERE posts.capital_slug = ?
       ORDER BY posts.created_at DESC`,
      [slug]
    );
    res.json({
      posts: posts.map((post) => ({
        id: post.id,
        content: post.content,
        createdAt: post.created_at,
        author: post.author_name
      }))
    });
  } catch (error) {
    console.error('Failed to load posts', error);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

app.post('/api/forums/:slug/posts', authMiddleware, async (req, res) => {
  const slug = sanitizeForumSlug(req.params.slug);
  if (!slug) {
    return res.status(400).json({ error: 'Invalid forum identifier' });
  }
  const { content } = req.body || {};
  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'Post content cannot be empty' });
  }
  if (content.length > 2000) {
    return res.status(400).json({ error: 'Post content is too long' });
  }
  try {
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    await db.run(
      `INSERT INTO posts (id, capital_slug, content, user_id, created_at) VALUES (?, ?, ?, ?, ?)`,
      [id, slug, content.trim(), req.user.id, createdAt]
    );
    res.status(201).json({
      post: {
        id,
        content: content.trim(),
        createdAt,
        author: req.user.name
      }
    });
  } catch (error) {
    console.error('Failed to create post', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  try {
    db = await initDatabase();
    app.listen(PORT, () => {
      console.log(`Expat Atlas server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server', error);
    process.exit(1);
  }
}

start();
