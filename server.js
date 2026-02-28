require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const pgSession  = require('connect-pg-simple')(session);
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const cors       = require('cors');
const cloudinary = require('cloudinary').v2;
const { pool, initDB } = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Cloudinary ─────────────────────────────────────────────────────────────
// Add CLOUDINARY_URL to Render env vars — looks like:
// cloudinary://API_KEY:API_SECRET@CLOUD_NAME
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

// ── Multer (memory — files go straight to Cloudinary) ─────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|png|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  },
});

// ── CORS — allow Netlify frontend ──────────────────────────────────────────
// Add FRONTEND_URL to Render env vars e.g. https://your-site.netlify.app
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:3000',
  'http://127.0.0.1:5500',
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('CORS blocked: ' + origin));
  },
  credentials: true,
}));

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
};

async function getUser(id) {
  const r = await pool.query(
    'SELECT id,first_name,last_name,email,bio,avatar_url,created_at FROM users WHERE id=$1', [id]
  );
  return r.rows[0];
}

// ══════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════

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
    res.json({ user: await getUser(r.rows[0].id) });
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
    req.session.userId = user.id;
    res.json({ user: await getUser(user.id) });
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

// ══════════════════════════════════════════════════════════════════════════
//  USERS / PROFILES
// ══════════════════════════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════════════════════════
//  POSTS
// ══════════════════════════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════════════════════════
//  LIKES
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    await pool.query('INSERT INTO likes (post_id,user_id) VALUES ($1,$2)', [req.params.id, req.session.userId]);
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

// ══════════════════════════════════════════════════════════════════════════
//  COMMENTS
// ══════════════════════════════════════════════════════════════════════════

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
  res.json({ comment: { ...r.rows[0], content: content.trim(), user_id: user.id, first_name: user.first_name, last_name: user.last_name, avatar_url: user.avatar_url } });
});

app.delete('/api/posts/:id/comments/:cid', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM comments WHERE id=$1 AND user_id=$2', [req.params.cid, req.session.userId]);
  res.json({ ok: true });
});

// ── Health check ───────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ── Start ──────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log('🚀 gSocial API running on port ' + PORT));
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});

// ── Self-ping every 10 minutes to keep Render free tier alive ─────────────
// Render uses HTTPS, so we ping our own /api/health endpoint
const https = require('https');

function selfPing() {
  const url = process.env.RENDER_EXTERNAL_URL || `https://gsocial-8axe.onrender.com`;
  https.get(`${url}/api/health`, (res) => {
    console.log(`🏓 Self-ping OK — ${new Date().toISOString()} (status ${res.statusCode})`);
  }).on('error', (err) => {
    console.warn(`⚠️  Self-ping failed: ${err.message}`);
  });
}

// Only ping in production so it doesn't run during local dev
if (process.env.NODE_ENV === 'production') {
  setInterval(selfPing, 10 * 60 * 1000); // every 10 minutes
  setTimeout(selfPing, 5000); // first ping 5s after boot
}
