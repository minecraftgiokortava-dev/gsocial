require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // ── Session store ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid"    varchar   NOT NULL COLLATE "default",
        "sess"   json      NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");`);

    // ── Users ─────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id         SERIAL PRIMARY KEY,
        first_name VARCHAR(64)  NOT NULL,
        last_name  VARCHAR(64)  NOT NULL,
        email      VARCHAR(255) NOT NULL UNIQUE,
        password   TEXT         NOT NULL,
        bio        TEXT,
        avatar_url TEXT,
        created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );
    `);

    // ── Friendships & Requests ────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS friendships (
        id        SERIAL PRIMARY KEY,
        user_id1  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user_id2  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id1, user_id2),
        CHECK(user_id1 < user_id2)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS friend_requests (
        id          SERIAL PRIMARY KEY,
        sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status      VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','declined')),
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(sender_id, receiver_id)
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_friend_req_recv ON friend_requests(receiver_id, status);`);

    // ── Groups (NEW) ──────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS groups (
        id          SERIAL PRIMARY KEY,
        name        VARCHAR(255) NOT NULL,
        description TEXT,
        creator_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS group_members (
        group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role       VARCHAR(50) DEFAULT 'member',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (group_id, user_id)
      );
    `);

    // ── Posts (UPDATED with group_id) ─────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        group_id   INTEGER REFERENCES groups(id) ON DELETE CASCADE,
        content    TEXT    NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    // Ensure the column exists if the table was already created before
    await client.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE;`);

    // ── Post images, Likes, Comments, Messages ────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS post_images (
        id      SERIAL PRIMARY KEY,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        url     TEXT    NOT NULL,
        sort    INTEGER NOT NULL DEFAULT 0
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS likes (
        id         SERIAL PRIMARY KEY,
        post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(post_id, user_id)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id         SERIAL PRIMARY KEY,
        post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content    TEXT    NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id          SERIAL PRIMARY KEY,
        sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content     TEXT    NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // ── Indexes ───────────────────────────────────────────────────────────────
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_user        ON posts(user_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_group       ON posts(group_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_created     ON posts(created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_likes_post        ON likes(post_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_comments_post     ON comments(post_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_sender   ON messages(sender_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_recv     ON messages(receiver_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_created  ON messages(created_at ASC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_post_images_post  ON post_images(post_id);`);

    await client.query('COMMIT');
    console.log('✅ Database initialized');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Database init error:', e);
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
