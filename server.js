require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const pgSession  = require('connect-pg-simple')(session);
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const cors       = require('cors');
const cloudinary = require('cloudinary').v2;
const https      = require('https');
const http       = require('http');
const { WebSocketServer } = require('ws');
const { pool, initDB } = require('./db');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 3000;

app.set('trust proxy', 1);

// ── Keep-Alive Ping ───────────────────────────────────────────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
setInterval(() => {
  const url = SELF_URL + '/api/health';
  const lib = url.startsWith('https') ? https : http;
  lib.get(url, r => console.log(`🏓 Keep-alive → ${r.statusCode}`))
     .on('error', e => console.warn('Keep-alive failed:', e.message));
}, 10 * 60 * 1000);

// ── Cloudinary ────────────────────────────────────────────────────────────────
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

// ── Multer ────────────────────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|png|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Only image files are allowed'), ok);
  },
});

// ── CORS ──────────────────────────────────────────────────────────────────────
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
    cb(new Error('CORS blocked: ' + origin));
  },
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Session ───────────────────────────────────────────────────────────────────
const sessionMiddleware = session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: false }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
});
app.use(sessionMiddleware);

// ══════════════════════════════════════════════════════════════════════════════
//  WEBSOCKET  (real-time messages + typing + announcements)
// ══════════════════════════════════════════════════════════════════════════════
const wss = new WebSocketServer({ server });
const clients = new Map(); // userId → Set<WebSocket>

wss.on('connection', (ws, req) => {
  sessionMiddleware(req, {}, () => {
    const userId = req.session?.userId;
    if (!userId) { ws.close(1008, 'Not authenticated'); return; }

    ws.userId = userId;
    if (!clients.has(userId)) clients.set(userId, new Set());
    clients.get(userId).add(ws);

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw);
        if (msg.type === 'typing')
          broadcastTo(msg.to, { type: 'typing', from: userId, name: msg.name });
        if (msg.type === 'stop_typing')
          broadcastTo(msg.to, { type: 'stop_typing', from: userId });
      } catch {}
    });

    ws.on('close', () => {
      clients.get(userId)?.delete(ws);
      if (!clients.get(userId)?.size) clients.delete(userId);
    });

    ws.on('error', () => {});
  });
});

function broadcastTo(userId, data) {
  const sockets = clients.get(parseInt(userId));
  if (!sockets) return;
  const payload = JSON.stringify(data);
  sockets.forEach(ws => { if (ws.readyState === 1) ws.send(payload); });
}

function broadcastAll(data) {
  const payload = JSON.stringify(data);
  clients.forEach(sockets =>
    sockets.forEach(ws => { if (ws.readyState === 1) ws.send(payload); })
  );
}

// ── Auth middleware ───────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
};

const requireAdmin = async (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  try {
    const r = await pool.query('SELECT role FROM users WHERE id=$1', [req.session.userId]);
    if (r.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  } catch { res.status(500).json({ error: 'Server error' }); }
};

async function getUser(id) {
  const r = await pool.query(
    'SELECT id,first_name,last_name,email,bio,avatar_url,role,created_at FROM users WHERE id=$1', [id]
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

  // ── Unique display name check ──
  try {
    const nameCheck = await pool.query(
      `SELECT id FROM users WHERE LOWER(first_name || ' ' || last_name) = LOWER($1)`,
      [`${first_name.trim()} ${last_name.trim()}`]
    );
    if (nameCheck.rowCount > 0)
      return res.status(400).json({ error: `The name "${first_name.trim()} ${last_name.trim()}" is already taken. Please choose a different name.` });

    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      'INSERT INTO users (first_name,last_name,email,password) VALUES ($1,$2,$3,$4) RETURNING id',
      [first_name.trim(), last_name.trim(), email.toLowerCase().trim(), hash]
    );
    req.session.userId = r.rows[0].id;
    req.session.save(async () => res.json({ user: await getUser(req.session.userId) }));
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Email already registered' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Invalid email/password' });
    req.session.userId = user.id;
    req.session.save(async () => res.json({ user: await getUser(user.id) }));
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  res.json({ user: await getUser(req.session.userId) });
});

// ══════════════════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/announcements/active', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.content, a.created_at, u.first_name, u.last_name
       FROM announcements a JOIN users u ON u.id = a.created_by
       WHERE a.active = TRUE ORDER BY a.created_at DESC LIMIT 1`
    );
    res.json({ announcement: rows[0] || null });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/announcements', requireAdmin, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  try {
    await pool.query('UPDATE announcements SET active=FALSE WHERE active=TRUE');
    await pool.query(
      'INSERT INTO announcements (content, created_by) VALUES ($1,$2)',
      [content.trim(), req.session.userId]
    );
    broadcastAll({ type: 'announcement', content: content.trim() });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/announcements/active', requireAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE announcements SET active=FALSE WHERE active=TRUE');
    broadcastAll({ type: 'announcement_stop' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, email, role, avatar_url, created_at,
        (SELECT COUNT(*)::int FROM posts WHERE user_id=users.id) AS post_count
       FROM users ORDER BY created_at DESC`
    );
    res.json({ users: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/users/:id/role', requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!['user','verified','admin'].includes(role))
    return res.status(400).json({ error: 'Invalid role' });
  try {
    await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.session.userId)
    return res.status(400).json({ error: "Can't delete your own account" });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/admin/posts', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at,
        u.id AS user_id, u.first_name, u.last_name, u.avatar_url, u.role,
        COUNT(DISTINCT l.id)::int AS likes_count,
        COUNT(DISTINCT c.id)::int AS comments_count,
        json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort))
          FILTER (WHERE pi.id IS NOT NULL) AS images
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN likes l ON l.post_id = p.id
      LEFT JOIN comments c ON c.post_id = p.id
      LEFT JOIN post_images pi ON pi.post_id = p.id
      GROUP BY p.id, u.id
      ORDER BY p.created_at DESC LIMIT 200
    `);
    res.json({ posts: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/posts/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM posts WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  USERS
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/users/search', requireAuth, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json({ users: [] });
  try {
    const { rows } = await pool.query(
      `SELECT id, first_name, last_name, avatar_url, role FROM users
       WHERE (first_name || ' ' || last_name) ILIKE $1 AND id != $2 LIMIT 10`,
      [`%${q}%`, req.session.userId]
    );
    res.json({ users: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/users/me', requireAuth, async (req, res) => {
  res.json({ user: await getUser(req.session.userId) });
});

app.get('/api/users/:id', requireAuth, async (req, res) => {
  const user = await getUser(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

app.put('/api/users/me', requireAuth, async (req, res) => {
  const { first_name, last_name, bio } = req.body;
  if (!first_name || !last_name) return res.status(400).json({ error: 'Name fields required' });

  // Unique name check (excluding self)
  try {
    const nameCheck = await pool.query(
      `SELECT id FROM users WHERE LOWER(first_name || ' ' || last_name) = LOWER($1) AND id != $2`,
      [`${first_name.trim()} ${last_name.trim()}`, req.session.userId]
    );
    if (nameCheck.rowCount > 0)
      return res.status(400).json({ error: `The name "${first_name.trim()} ${last_name.trim()}" is already taken.` });

    await pool.query(
      'UPDATE users SET first_name=$1, last_name=$2, bio=$3 WHERE id=$4',
      [first_name.trim(), last_name.trim(), bio || null, req.session.userId]
    );
    res.json({ user: await getUser(req.session.userId) });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/users/me/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  try {
    const url = await uploadToCloudinary(req.file.buffer, 'gsocial/avatars');
    await pool.query('UPDATE users SET avatar_url=$1 WHERE id=$2', [url, req.session.userId]);
    res.json({ avatar_url: url });
  } catch (e) { res.status(500).json({ error: 'Upload failed' }); }
});

app.get('/api/users/:id/posts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.first_name, u.last_name, u.avatar_url, u.role,
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
      WHERE p.user_id = $2
      GROUP BY p.id, u.id
      ORDER BY p.created_at DESC LIMIT 50
    `, [req.session.userId, req.params.id]);
    res.json({ posts: rows });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  FRIENDS
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.avatar_url, u.role
       FROM friendships f
       JOIN users u ON u.id = CASE WHEN f.user_id1=$1 THEN f.user_id2 ELSE f.user_id1 END
       WHERE f.user_id1=$1 OR f.user_id2=$1`,
      [req.session.userId]
    );
    res.json({ friends: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/friends/:id', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM friendships WHERE user_id1=least($1::int,$2::int) AND user_id2=greatest($1::int,$2::int)`,
      [req.session.userId, parseInt(req.params.id)]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/friends/requests', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT u.id, u.first_name, u.last_name, u.avatar_url, u.role, fr.created_at
       FROM friend_requests fr JOIN users u ON u.id = fr.sender_id
       WHERE fr.receiver_id=$1 AND fr.status='pending' ORDER BY fr.created_at DESC`,
      [req.session.userId]
    );
    res.json({ requests: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/requests/:id', requireAuth, async (req, res) => {
  const receiverId = parseInt(req.params.id);
  if (receiverId === req.session.userId) return res.status(400).json({ error: "Can't add yourself" });
  try {
    const existing = await pool.query(
      `SELECT 1 FROM friendships WHERE user_id1=least($1::int,$2::int) AND user_id2=greatest($1::int,$2::int)`,
      [req.session.userId, receiverId]
    );
    if (existing.rowCount) return res.status(400).json({ error: 'Already friends' });
    const dup = await pool.query(
      `SELECT 1 FROM friend_requests WHERE sender_id=$1 AND receiver_id=$2 AND status='pending'`,
      [req.session.userId, receiverId]
    );
    if (dup.rowCount) return res.status(400).json({ error: 'Request already sent' });
    const reverse = await pool.query(
      `SELECT id FROM friend_requests WHERE sender_id=$1 AND receiver_id=$2 AND status='pending'`,
      [receiverId, req.session.userId]
    );
    if (reverse.rowCount) {
      await pool.query(
        `INSERT INTO friendships (user_id1,user_id2) VALUES (least($1::int,$2::int),greatest($1::int,$2::int)) ON CONFLICT DO NOTHING`,
        [req.session.userId, receiverId]
      );
      await pool.query(`UPDATE friend_requests SET status='accepted' WHERE id=$1`, [reverse.rows[0].id]);
      return res.json({ ok: true, auto_accepted: true });
    }
    await pool.query(`INSERT INTO friend_requests (sender_id,receiver_id) VALUES ($1,$2)`, [req.session.userId, receiverId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/friends/requests/:id/accept', requireAuth, async (req, res) => {
  const senderId = parseInt(req.params.id);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      `UPDATE friend_requests SET status='accepted' WHERE sender_id=$1 AND receiver_id=$2 AND status='pending' RETURNING id`,
      [senderId, req.session.userId]
    );
    if (!r.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Request not found' }); }
    await client.query(
      `INSERT INTO friendships (user_id1,user_id2) VALUES (least($1::int,$2::int),greatest($1::int,$2::int)) ON CONFLICT DO NOTHING`,
      [req.session.userId, senderId]
    );
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

app.post('/api/friends/requests/:id/decline', requireAuth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE friend_requests SET status='declined' WHERE sender_id=$1 AND receiver_id=$2 AND status='pending'`,
      [parseInt(req.params.id), req.session.userId]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  POSTS
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/posts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.first_name, u.last_name, u.avatar_url, u.role,
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
      ORDER BY p.created_at DESC LIMIT 50
    `, [req.session.userId]);
    res.json({ posts: rows });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts', requireAuth, upload.array('images', 9), async (req, res) => {
  const { content } = req.body;
  if (!content?.trim() && !req.files?.length) return res.status(400).json({ error: 'Post cannot be empty' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      'INSERT INTO posts (user_id,content) VALUES ($1,$2) RETURNING id',
      [req.session.userId, content?.trim() || '']
    );
    const postId = r.rows[0].id;
    if (req.files?.length) {
      const urls = await Promise.all(req.files.map(f => uploadToCloudinary(f.buffer, 'gsocial/posts')));
      for (let i = 0; i < urls.length; i++)
        await client.query('INSERT INTO post_images (post_id,url,sort) VALUES ($1,$2,$3)', [postId, urls[i], i]);
    }
    await client.query('COMMIT');
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.first_name, u.last_name, u.avatar_url, u.role,
        0::int AS likes_count, 0::int AS comments_count, false AS liked_by_me,
        json_agg(DISTINCT jsonb_build_object('url', pi.url, 'sort', pi.sort)) FILTER (WHERE pi.id IS NOT NULL) AS images
      FROM posts p JOIN users u ON u.id = p.user_id
      LEFT JOIN post_images pi ON pi.post_id = p.id
      WHERE p.id=$1 GROUP BY p.id, u.id
    `, [postId]);
    broadcastAll({ type: 'new_post', post: rows[0] });
    res.json({ post: rows[0] });
  } catch (e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'Server error' }); }
  finally { client.release(); }
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  try {
    // Allow post owner OR admin to delete
    const r = await pool.query('SELECT role FROM users WHERE id=$1', [req.session.userId]);
    const isAdmin = r.rows[0]?.role === 'admin';
    const del = await pool.query(
      isAdmin ? 'DELETE FROM posts WHERE id=$1 RETURNING id'
              : 'DELETE FROM posts WHERE id=$1 AND user_id=$2 RETURNING id',
      isAdmin ? [req.params.id] : [req.params.id, req.session.userId]
    );
    if (!del.rowCount) return res.status(403).json({ error: 'Not authorized or post not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    await pool.query('INSERT INTO likes (post_id,user_id) VALUES ($1,$2)', [req.params.id, req.session.userId]);
    const r = await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1', [req.params.id]);
    res.json({ liked: true, count: r.rows[0].count });
  } catch { res.status(400).json({ error: 'Already liked' }); }
});

app.delete('/api/posts/:id/like', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM likes WHERE post_id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
    const r = await pool.query('SELECT COUNT(*)::int AS count FROM likes WHERE post_id=$1', [req.params.id]);
    res.json({ liked: false, count: r.rows[0].count });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/posts/:id/comments', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.content, c.created_at, c.user_id, u.first_name, u.last_name, u.avatar_url, u.role
      FROM comments c JOIN users u ON u.id = c.user_id
      WHERE c.post_id=$1 ORDER BY c.created_at ASC
    `, [req.params.id]);
    res.json({ comments: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/posts/:id/comments', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  try {
    const r = await pool.query(
      'INSERT INTO comments (post_id,user_id,content) VALUES ($1,$2,$3) RETURNING id, created_at',
      [req.params.id, req.session.userId, content.trim()]
    );
    const user = await getUser(req.session.userId);
    res.json({ comment: { id: r.rows[0].id, content: content.trim(), created_at: r.rows[0].created_at, user_id: user.id, first_name: user.first_name, last_name: user.last_name, avatar_url: user.avatar_url, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/posts/:postId/comments/:commentId', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      'DELETE FROM comments WHERE id=$1 AND user_id=$2 RETURNING id',
      [req.params.commentId, req.session.userId]
    );
    if (!r.rowCount) return res.status(403).json({ error: 'Not authorized' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  MESSAGES
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/messages/conversations', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT DISTINCT ON (other_user) other_user AS user_id,
        u.first_name, u.last_name, u.avatar_url, u.role,
        m.content AS last_message, m.created_at AS last_ts
      FROM (
        SELECT CASE WHEN sender_id=$1 THEN receiver_id ELSE sender_id END AS other_user, id
        FROM messages WHERE sender_id=$1 OR receiver_id=$1
      ) sub
      JOIN messages m ON m.id=sub.id JOIN users u ON u.id=sub.other_user
      ORDER BY other_user, m.created_at DESC
    `, [req.session.userId]);
    rows.sort((a,b) => new Date(b.last_ts)-new Date(a.last_ts));
    res.json({ conversations: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, content, created_at, sender_id, receiver_id, (sender_id=$1) AS from_me
      FROM messages WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1)
      ORDER BY created_at ASC
    `, [req.session.userId, req.params.userId]);
    res.json({ messages: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/messages/:userId', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
  try {
    const r = await pool.query(
      'INSERT INTO messages (sender_id,receiver_id,content) VALUES ($1,$2,$3) RETURNING id, created_at',
      [req.session.userId, req.params.userId, content.trim()]
    );
    const msg = { id: r.rows[0].id, content: content.trim(), created_at: r.rows[0].created_at, sender_id: req.session.userId, receiver_id: parseInt(req.params.userId), from_me: true };
    // Push message to receiver in real-time via WebSocket
    broadcastTo(parseInt(req.params.userId), { type: 'message', message: { ...msg, from_me: false } });
    res.json({ message: msg });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
//  GROUPS
// ══════════════════════════════════════════════════════════════════════════════
async function ensureGroupsTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS groups (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, description TEXT,
        privacy VARCHAR(20) NOT NULL DEFAULT 'public', emoji VARCHAR(10) NOT NULL DEFAULT '👥',
        creator_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL DEFAULT 'member', joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (group_id, user_id)
      );
    `);
    await pool.query(`DO $$ BEGIN ALTER TABLE posts ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE; EXCEPTION WHEN duplicate_column THEN NULL; END $$;`);
    console.log('✅ Groups tables ready');
  } catch (e) { console.error('⚠️ ensureGroupsTables:', e.message); }
}

app.get('/api/groups', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT g.id, g.name, g.description, g.privacy, g.emoji, g.created_at, g.creator_id,
        COUNT(DISTINCT gm.user_id)::int AS member_count, BOOL_OR(gm.user_id=$1) AS is_member
      FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id
      GROUP BY g.id ORDER BY g.created_at DESC
    `, [req.session.userId]);
    res.json({ groups: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/groups/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT g.id, g.name, g.description, g.privacy, g.emoji, g.created_at, g.creator_id,
        COUNT(DISTINCT gm.user_id)::int AS member_count, BOOL_OR(gm.user_id=$1) AS is_member
      FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id WHERE g.id=$2 GROUP BY g.id
    `, [req.session.userId, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Group not found' });
    res.json({ group: rows[0] });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/groups', requireAuth, async (req, res) => {
  const { name, description, privacy, emoji } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Group name required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query(
      `INSERT INTO groups (name,description,privacy,emoji,creator_id) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [name.trim(), description?.trim()||null, privacy||'public', emoji||'👥', req.session.userId]
    );
    const groupId = r.rows[0].id;
    await client.query(`INSERT INTO group_members (group_id,user_id,role) VALUES ($1,$2,'admin')`, [groupId, req.session.userId]);
    await client.query('COMMIT');
    const { rows } = await pool.query(`SELECT g.*, COUNT(gm.user_id)::int AS member_count, true AS is_member FROM groups g LEFT JOIN group_members gm ON gm.group_id=g.id WHERE g.id=$1 GROUP BY g.id`, [groupId]);
    res.json({ group: rows[0] });
  } catch (e) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Server error: '+e.message }); }
  finally { client.release(); }
});

app.post('/api/groups/:id/join', requireAuth, async (req, res) => {
  try {
    await pool.query(`INSERT INTO group_members (group_id,user_id,role) VALUES ($1,$2,'member') ON CONFLICT DO NOTHING`, [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/groups/:id/join', requireAuth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM group_members WHERE group_id=$1 AND user_id=$2`, [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/groups/:id/members', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.first_name, u.last_name, u.avatar_url, u.role AS user_role, gm.role AS group_role, gm.joined_at
      FROM group_members gm JOIN users u ON u.id=gm.user_id
      WHERE gm.group_id=$1 ORDER BY gm.role='admin' DESC, gm.joined_at ASC
    `, [req.params.id]);
    res.json({ members: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/groups/:id/posts', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.content, p.created_at, u.id AS user_id, u.first_name, u.last_name, u.avatar_url, u.role,
        COUNT(DISTINCT l.id)::int AS likes_count, COUNT(DISTINCT c.id)::int AS comments_count, BOOL_OR(l.user_id=$1) AS liked_by_me
      FROM posts p JOIN users u ON u.id=p.user_id
      LEFT JOIN likes l ON l.post_id=p.id LEFT JOIN comments c ON c.post_id=p.id
      WHERE p.group_id=$2 GROUP BY p.id, u.id ORDER BY p.created_at DESC LIMIT 50
    `, [req.session.userId, req.params.id]);
    res.json({ posts: rows });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/groups/:id/posts', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Post cannot be empty' });
  try {
    const mem = await pool.query(`SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2`, [req.params.id, req.session.userId]);
    if (!mem.rowCount) return res.status(403).json({ error: 'You must join the group to post' });
    const r = await pool.query(`INSERT INTO posts (user_id,content,group_id) VALUES ($1,$2,$3) RETURNING id`, [req.session.userId, content.trim(), req.params.id]);
    res.json({ ok: true, post_id: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ── Startup ───────────────────────────────────────────────────────────────────
initDB()
  .then(() => ensureGroupsTables())
  .then(() => {
    server.listen(PORT, () => console.log('🚀 API + WebSocket on port ' + PORT));
  });
