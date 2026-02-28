require('dotenv').config();
const express   = require('express');
const session   = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt    = require('bcryptjs');
const multer    = require('multer');
const cors      = require('cors');
const cloudinary = require('cloudinary').v2;
const { pool, initDB } = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Cloudinary ──────────────────────────────────────────────────────────────
cloudinary.config({ cloudinary_url: process.env.CLOUDINARY_URL });

function uploadToCloudinary(buffer, folder = 'gsocial/posts') {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: 'image' },
      (err, result) => err ? reject(err) : resolve(result.secure_url)
    );
    stream.end(buffer);
  });
}

// ── Multer ──────────────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|png|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  },
});

// ── CORS ────────────────────────────────────────────────────────────────────
// ⚠️  FIX: was blocking onrender.com origins. Now allows any subdomain of
//    onrender.com + any origin the user sets via FRONTEND_URL env var.
app.use(cors({
  origin: (origin, cb) => {
    // No origin = same-origin request, Postman, curl, mobile apps → allow
    if (!origin) return cb(null, true);

    const allowed = [
      // Local development
      /^https?:\/\/localhost(:\d+)?$/,
      /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
      // Render deployments (backend + frontend on the same platform)
      /^https:\/\/[a-z0-9-]+\.onrender\.com$/,
      // Netlify
      /^https:\/\/[a-z0-9-]+\.netlify\.app$/,
    ];

    // Also allow whatever FRONTEND_URL is set to in env vars
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) {
      return cb(null, true);
    }

    if (allowed.some(re => re.test(origin))) return cb(null, true);

    console.warn('CORS blocked:', origin);
    cb(new Error('CORS blocked: ' + origin));
  },
  credentials: true,
}));

// ── Body parsers ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Sessions ────────────────────────────────────────────────────────────────
// ⚠️  FIX: sameSite must be 'none' in production so cross-origin cookies work.
//    The old code used 'lax' which silently drops cookies on cross-site requests
//    (frontend on gsocial-8axe.onrender.com → backend on a different Render URL).
app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    secure: process.env.NODE_ENV === 'production',   // HTTPS only in prod
    httpOnly: true,
    // 'none' required for cross-site cookies (frontend & backend on different domains)
    // 'lax' only works when frontend and backend share the same domain
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));

// ── Auth middleware ─────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
};

async function getUser(id) {
  const r = await pool.query(
    'SELECT id,first_name,last_name,email,bio,avatar_url,created_at FROM users WHERE id=$1',
    [id]
  );
  return r.rows[0];
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════════

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
    const userId = r.rows[0].id;
    // ⚠️  FIX: Use session.save() to guarantee the cookie is written before
    //    the response is sent — without this, /api/posts 401s right after signup.
    req.session.userId = userId;
    req.session.save(async (err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Session error' });
      }
      res.json({ user: await getUser(userId) });
    });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Invalid email or password' });
    // ⚠️  FIX: same session.save() guarantee as signup
    req.session.userId = user.id;
    req.session.save(async (err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ error: 'Session error' });
      }
      res.json({ user: await getUser(user.id) });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  const user = await getUser(req.session.userId);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  res.json({ user });
});

// ══════════════════════════════════════════════════════════════════════════════
//  USERS / PROFILES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/users/:id', requireAuth, async (req, res) => {
  const user = await getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

app.put('/api/users/me', requireAuth, async (req, res) => {
  const { first_name, last_name, bio } = req.body;
  await pool.query(
    'UPDATE users SET first_name=$1, last_name=$2, bio=$3 WHERE id=$4',
    [first_name, last_name, bio, req.session.userId]
  );
  res.json({ user: await getUser(req.session.userId) });
});

app.post('/api/users/me/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const url = await uploadToCloudinary(req.file.buffer, 'gsocial/avatars');
    await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [url, req.session.userId]);
    res.json({ avatar_url: url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
//  POSTS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/posts', requireAuth, async (req, res) => {
  try {
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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/users/:id/posts', requireAuth, async (req, res) => {
  try {
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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/posts', requireAuth, upload.array('images', 9), async (req, res) => {
  const { content } = req.body;
  if (!content?.trim() && !req.files?.length)
    return res.status(400).json({ error: 'Post cannot be empty' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      'INSERT INTO posts (user_id,content) VALUES ($1,$2) RETURNING id',
      [req.session.userId, content?.trim() || '']
    );
    const postId = r.rows[0].id;

    if (req.files?.length) {
      const urls = await Promise.all(
        req.files.map(f => uploadToCloudinary(f.buffer, 'gsocial/posts'))
      );
      for (let i = 0; i < urls.length; i++) {
        await client.query(
          'INSERT INTO post_images (post_id,url,sort) VALUES ($1,$2,$3)',
          [postId, urls[i], i]
        );
      }
    }

    await client.query('COMMIT');

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

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const r = await pool.query(
    'DELETE FROM posts WHERE id=$1 AND user_id=$2 RETURNING id',
    [req.params.id, req.session.userId]
  );
  if (!r.rowCount) return res.status(403).json({ error: 'Not allowed' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
//  LIKES
// ══════════════════════════════════════════════════════════════════════════════

app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO likes (post_id,user_id) VALUES ($1,$2)',
      [req.params.id, req.session.userId]
    );
    const r = await pool.query(
      'SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1',
      [req.params.id]
    );
    res.json({ liked: true, count: r.rows[0].count });
  } catch {
    res.status(400).json({ error: 'Already liked' });
  }
});

app.delete('/api/posts/:id/like', requireAuth, async (req, res) => {
  await pool.query(
    'DELETE FROM likes WHERE post_id=$1 AND user_id=$2',
    [req.params.id, req.session.userId]
  );
  const r = await pool.query(
    'SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1',
    [req.params.id]
  );
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
    'INSERT INTO comments (post_id,user_id,content) VALUES ($1,$2,$3) RETURNING id,created_at',
    [req.params.id, req.session.userId, content.trim()]
  );
  const user = await getUser(req.session.userId);
  res.json({
    comment: {
      ...r.rows[0],
      content: content.trim(),
      user_id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      avatar_url: user.avatar_url,
    }
  });
});

app.delete('/api/posts/:id/comments/:cid', requireAuth, async (req, res) => {
  await pool.query(
    'DELETE FROM comments WHERE id=$1 AND user_id=$2',
    [req.params.cid, req.session.userId]
  );
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════════
//  MESSAGES  (NEW)
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/messages/conversations — list of unique users you've chatted with
app.get('/api/messages/conversations', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (other_id)
        other_id AS user_id,
        u.first_name, u.last_name, u.avatar_url,
        m.content AS last_message,
        m.created_at AS last_ts,
        COUNT(m2.id) FILTER (WHERE m2.read = FALSE AND m2.receiver_id = $1)::int AS unread_count
      FROM (
        SELECT
          CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS other_id,
          id, content, created_at
        FROM messages
        WHERE sender_id = $1 OR receiver_id = $1
        ORDER BY created_at DESC
      ) m
      JOIN users u ON u.id = m.other_id
      LEFT JOIN messages m2 ON (
        (m2.sender_id = m.other_id AND m2.receiver_id = $1)
      )
      GROUP BY other_id, u.first_name, u.last_name, u.avatar_url, m.content, m.created_at
      ORDER BY other_id, m.created_at DESC
    `, [req.session.userId]);
    res.json({ conversations: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/messages/:userId — get message thread with a specific user
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        m.id, m.content, m.created_at, m.read,
        m.sender_id, m.receiver_id,
        (m.sender_id = $1) AS from_me
      FROM messages m
      WHERE (m.sender_id = $1 AND m.receiver_id = $2)
         OR (m.sender_id = $2 AND m.receiver_id = $1)
      ORDER BY m.created_at ASC
    `, [req.session.userId, req.params.userId]);

    // Mark received messages as read
    await pool.query(`
      UPDATE messages SET read = TRUE
      WHERE sender_id = $2 AND receiver_id = $1 AND read = FALSE
    `, [req.session.userId, req.params.userId]);

    res.json({ messages: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/messages/:userId — send a message to a user
app.post('/api/messages/:userId', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Message cannot be empty' });

  // Can't message yourself
  if (parseInt(req.params.userId) === req.session.userId)
    return res.status(400).json({ error: "You can't message yourself" });

  // Make sure target user exists
  const target = await getUser(req.params.userId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  try {
    const r = await pool.query(
      'INSERT INTO messages (sender_id,receiver_id,content) VALUES ($1,$2,$3) RETURNING id,created_at',
      [req.session.userId, req.params.userId, content.trim()]
    );
    res.json({
      message: {
        ...r.rows[0],
        content: content.trim(),
        sender_id: req.session.userId,
        receiver_id: parseInt(req.params.userId),
        from_me: true,
        read: false,
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/messages/:messageId — delete a single message (own only)
app.delete('/api/messages/:messageId', requireAuth, async (req, res) => {
  const r = await pool.query(
    'DELETE FROM messages WHERE id=$1 AND sender_id=$2 RETURNING id',
    [req.params.messageId, req.session.userId]
  );
  if (!r.rowCount) return res.status(403).json({ error: 'Not allowed' });
  res.json({ ok: true });
});

// ── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ── Start ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log('🚀 gSocial API running on port ' + PORT));
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});

// ── Self-ping every 10 min to keep Render free tier alive ────────────────────
const https = require('https');

function selfPing() {
  const url = process.env.RENDER_EXTERNAL_URL || 'https://gsocial-8axe.onrender.com';
  https.get(`${url}/api/health`, (res) => {
    console.log(`🏓 Self-ping OK — ${new Date().toISOString()} (status ${res.statusCode})`);
  }).on('error', (err) => {
    console.warn(`⚠️  Self-ping failed: ${err.message}`);
  });
}

if (process.env.NODE_ENV === 'production') {
  setInterval(selfPing, 10 * 60 * 1000);
  setTimeout(selfPing, 5000);
}
