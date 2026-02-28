require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const pgSession  = require('connect-pg-simple')(session);
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const { pool, initDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Multer (photo uploads) ─────────────────────────────────────────────────
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename:    (req, file, cb) => {
    const ext  = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB per file
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|png|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files allowed'), ok);
  },
});

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
}));

// ── Auth middleware ────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
};

// ── Helper: get user by id ─────────────────────────────────────────────────
async function getUser(id) {
  const r = await pool.query('SELECT id,first_name,last_name,email,bio,avatar_url,created_at FROM users WHERE id=$1', [id]);
  return r.rows[0];
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  if (!first_name || !last_name || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (first_name,last_name,email,password) VALUES ($1,$2,$3,$4) RETURNING id',
      [first_name.trim(), last_name.trim(), email.toLowerCase().trim(), hash]
    );
    req.session.userId = r.rows[0].id;
    const user = await getUser(r.rows[0].id);
    res.json({ user });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Log in
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Invalid email or password' });
    req.session.userId = user.id;
    const safe = await getUser(user.id);
    res.json({ user: safe });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Log out
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Current user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await getUser(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  res.json({ user });
});

// ══════════════════════════════════════════════════════════════════════════════
//  USER / PROFILE ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Get profile
app.get('/api/users/:id', requireAuth, async (req, res) => {
  const user = await getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// Update profile (bio)
app.put('/api/users/me', requireAuth, async (req, res) => {
  const { first_name, last_name, bio } = req.body;
  await pool.query(
    'UPDATE users SET first_name=$1, last_name=$2, bio=$3 WHERE id=$4',
    [first_name, last_name, bio, req.session.userId]
  );
  const user = await getUser(req.session.userId);
  res.json({ user });
});

// Upload avatar
app.post('/api/users/me/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [url, req.session.userId]);
  res.json({ avatar_url: url });
});

// ══════════════════════════════════════════════════════════════════════════════
//  POSTS ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// Get feed (all posts, newest first)
app.get('/api/posts', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      p.id, p.content, p.created_at,
      u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
      COUNT(DISTINCT l.id)::int AS likes_count,
      COUNT(DISTINCT c.id)::int AS comments_count,
      BOOL_OR(l.user_id = $1) AS liked_by_me,
      json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort))
        FILTER (WHERE pi.id IS NOT NULL) AS images
    FROM posts p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN likes l ON l.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    LEFT JOIN post_images pi ON pi.post_id = p.id
    GROUP BY p.id, u.id
    ORDER BY p.created_at DESC
    LIMIT 50
  `, [req.session.userId]);
  res.json({ posts: rows });
});

// Get single user's posts
app.get('/api/users/:id/posts', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      p.id, p.content, p.created_at,
      u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
      COUNT(DISTINCT l.id)::int AS likes_count,
      COUNT(DISTINCT c.id)::int AS comments_count,
      BOOL_OR(l.user_id = $2) AS liked_by_me,
      json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort))
        FILTER (WHERE pi.id IS NOT NULL) AS images
    FROM posts p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN likes l ON l.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    LEFT JOIN post_images pi ON pi.post_id = p.id
    WHERE p.user_id = $1
    GROUP BY p.id, u.id
    ORDER BY p.created_at DESC
  `, [req.params.id, req.session.userId]);
  res.json({ posts: rows });
});

// Create post (with optional images)
app.post('/api/posts', requireAuth, upload.array('images', 9), async (req, res) => {
  const { content } = req.body;
  if (!content?.trim() && !req.files?.length)
    return res.status(400).json({ error: 'Post cannot be empty' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING id',
      [req.session.userId, content?.trim() || '']
    );
    const postId = r.rows[0].id;

    if (req.files?.length) {
      for (let i = 0; i < req.files.length; i++) {
        const url = `/uploads/${req.files[i].filename}`;
        await client.query('INSERT INTO post_images (post_id, url, sort) VALUES ($1,$2,$3)', [postId, url, i]);
      }
    }

    await client.query('COMMIT');

    // Return full post
    const { rows } = await pool.query(`
      SELECT
        p.id, p.content, p.created_at,
        u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
        0::int AS likes_count, 0::int AS comments_count, false AS liked_by_me,
        json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort))
          FILTER (WHERE pi.id IS NOT NULL) AS images
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN post_images pi ON pi.post_id = p.id
      WHERE p.id = $1
      GROUP BY p.id, u.id
    `, [postId]);

    res.json({ post: rows[0] });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Delete post
app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const r = await pool.query('DELETE FROM posts WHERE id=$1 AND user_id=$2 RETURNING id', [req.params.id, req.session.userId]);
  if (!r.rowCount) return res.status(403).json({ error: 'Not allowed' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
//  LIKES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    await pool.query('INSERT INTO likes (post_id, user_id) VALUES ($1,$2)', [req.params.id, req.session.userId]);
    const r = await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1', [req.params.id]);
    res.json({ liked: true, count: r.rows[0].count });
  } catch {
    res.status(400).json({ error: 'Already liked' });
  }
});

app.delete('/api/posts/:id/like', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM likes WHERE post_id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  const r = await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1', [req.params.id]);
  res.json({ liked: false, count: r.rows[0].count });
});

// ══════════════════════════════════════════════════════════════════════════════
//  COMMENTS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.id, c.content, c.created_at,
           u.id AS user_id, u.first_name, u.last_name, u.avatar_url
    FROM comments c
    JOIN users u ON u.id = c.user_id
    WHERE c.post_id = $1
    ORDER BY c.created_at ASC
  `, [req.params.id]);
  res.json({ comments: rows });
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  const r = await pool.query(
    'INSERT INTO comments (post_id, user_id, content) VALUES ($1,$2,$3) RETURNING id, created_at',
    [req.params.id, req.session.userId, content.trim()]
  );
  const user = await getUser(req.session.userId);
  res.json({ comment: { ...r.rows[0], content: content.trim(), user_id: user.id, first_name: user.first_name, last_name: user.last_name, avatar_url: user.avatar_url } });
});

app.delete('/api/posts/:id/comments/:cid', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM comments WHERE id=$1 AND user_id=$2', [req.params.cid, req.session.userId]);
  res.json({ ok: true });
});

// ── Fallback: serve index for all non-API routes ───────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ──────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 gSocial running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
