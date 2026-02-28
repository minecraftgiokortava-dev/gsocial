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

app.set('trust proxy', 1);

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

// ── CORS ─────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  /^https?:\/\/localhost(:\d+)?$/,
  /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
  /^https:\/\/[a-z0-9-]+\.netlify\.app$/,
  /^https:\/\/[a-z0-9-]+\.onrender\.com$/,
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.some(re => re.test(origin))) return cb(null, true);
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) return cb(null, true);
    console.warn('❌ CORS blocked:', origin);
    cb(new Error('CORS blocked: ' + origin));
  },
  credentials: true,
}));

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

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════════════════
app.post('/api/auth/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  if (!first_name || !last_name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (first_name,last_name,email,password) VALUES ($1,$2,$3,$4) RETURNING id',
      [first_name.trim(), last_name.trim(), email.toLowerCase().trim(), hash]
    );
    req.session.userId = r.rows[0].id;
    req.session.save(async () => res.json({ user: await getUser(req.session.userId) }));
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid email/password' });
    req.session.userId = user.id;
    req.session.save(async () => res.json({ user: await getUser(user.id) }));
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/auth/me', requireAuth, async (req, res) => { res.json({ user: await getUser(req.session.userId) }); });

// ══════════════════════════════════════════════════════════════════════════════
//  USERS & FRIENDS (NEW SEARCH AND ADD FRIEND LOGIC)
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/users/search', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json({ users: [] });
  try {
    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, avatar_url FROM users 
       WHERE (first_name || ' ' || last_name) ILIKE $1 AND id != $2 LIMIT 10`,
      [`%${q}%`, req.session.userId]
    );
    res.json({ users: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/:id', requireAuth, async (req, res) => {
  const friendId = parseInt(req.params.id);
  if (friendId === req.session.userId) return res.status(400).json({ error: "Can't add yourself" });
  try {
    await pool.query(
      `INSERT INTO friendships (user_id1, user_id2) VALUES (least($1::int, $2::int), greatest($1::int, $2::int)) ON CONFLICT DO NOTHING`,
      [req.session.userId, friendId]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.avatar_url 
       FROM friendships f 
       JOIN users u ON u.id = CASE WHEN f.user_id1 = $1 THEN f.user_id2 ELSE f.user_id1 END
       WHERE f.user_id1 = $1 OR f.user_id2 = $1`,
      [req.session.userId]
    );
    res.json({ friends: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/:id', requireAuth, async (req, res) => { res.json({ user: await getUser(req.params.id) }); });

app.put('/api/users/me', requireAuth, async (req, res) => {
  const { first_name, last_name, bio } = req.body;
  await pool.query('UPDATE users SET first_name=$1, last_name=$2, bio=$3 WHERE id=$4', [first_name, last_name, bio, req.session.userId]);
  res.json({ user: await getUser(req.session.userId) });
});

app.post('/api/users/me/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const url = await uploadToCloudinary(req.file.buffer, 'gsocial/avatars');
    await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [url, req.session.userId]);
    res.json({ avatar_url: url });
  } catch (e) { res.status(500).json({ error: 'Upload failed' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  POSTS, LIKES, COMMENTS, MESSAGES (Kept Exactly the Same)
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/posts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.first_name, u.last_name, u.avatar_url,
        COUNT(DISTINCT l.id)::int AS likes_count, COUNT(DISTINCT c.id)::int AS comments_count,
        BOOL_OR(l.user_id = $1) AS liked_by_me,
        json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort)) FILTER (WHERE pi.id IS NOT NULL) AS images
      FROM posts p JOIN users u ON u.id = p.user_id
      LEFT JOIN likes l ON l.post_id = p.id LEFT JOIN comments c ON c.post_id = p.id LEFT JOIN post_images pi ON pi.post_id = p.id
      GROUP BY p.id, u.id ORDER BY p.created_at DESC LIMIT 50
    `, [req.session.userId]);
    res.json({ posts: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts', requireAuth, upload.array('images', 9), async (req, res) => {
  const { content } = req.body;
  if (!content?.trim() && !req.files?.length) return res.status(400).json({ error: 'Post cannot be empty' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query('INSERT INTO posts (user_id,content) VALUES ($1,$2) RETURNING id', [req.session.userId, content?.trim() || '']);
    const postId = r.rows[0].id;
    if (req.files?.length) {
      const urls = await Promise.all(req.files.map(f => uploadToCloudinary(f.buffer, 'gsocial/posts')));
      for (let i = 0; i < urls.length; i++) await client.query('INSERT INTO post_images (post_id,url,sort) VALUES ($1,$2,$3)', [postId, urls[i], i]);
    }
    await client.query('COMMIT');
    res.json({ post: { id: postId } }); // Simplified return for brevity
  } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Server error' }); } finally { client.release(); }
});

app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try { await pool.query('INSERT INTO likes (post_id,user_id) VALUES ($1,$2)', [req.params.id, req.session.userId]); res.json({ liked: true });
  } catch { res.status(400).json({ error: 'Already liked' }); }
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const r = await pool.query('INSERT INTO comments (post_id,user_id,content) VALUES ($1,$2,$3) RETURNING id', [req.params.id, req.session.userId, req.body.content]);
  res.json({ comment: r.rows[0] });
});

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, content, created_at, sender_id, receiver_id, (sender_id=$1) AS from_me FROM messages
      WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1) ORDER BY created_at ASC
    `, [req.session.userId, req.params.userId]);
    res.json({ messages: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/messages/:userId', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('INSERT INTO messages (sender_id,receiver_id,content) VALUES ($1,$2,$3) RETURNING id', [req.session.userId, req.params.userId, req.body.content]);
    res.json({ message: r.rows[0] });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

initDB().then(() => { app.listen(PORT, () => console.log('🚀 API on port ' + PORT)); });
