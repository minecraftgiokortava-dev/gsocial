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

    // ── Users (with role column) ──────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id          SERIAL PRIMARY KEY,
        first_name  VARCHAR(64)  NOT NULL,
        last_name   VARCHAR(64)  NOT NULL,
        email       VARCHAR(255) NOT NULL UNIQUE,
        password    TEXT         NOT NULL,
        bio         TEXT,
        avatar_url  TEXT,
        role        VARCHAR(16)  NOT NULL DEFAULT 'user',
        created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );
    `);
    // Safe migration: add role if table already existed without it
    await client.query(`DO $$ BEGIN ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user'; EXCEPTION WHEN duplicate_column THEN NULL; END $$;`);

    // ── Announcements ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id         SERIAL PRIMARY KEY,
        content    TEXT        NOT NULL,
        active     BOOLEAN     NOT NULL DEFAULT TRUE,
        created_by INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // ── Friendships ───────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS friendships (
        id         SERIAL PRIMARY KEY,
        user_id1   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        user_id2   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id1, user_id2),
        CHECK(user_id1 < user_id2)
      );
    `);

    // ── Friend Requests ───────────────────────────────────────────────────────
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

    // ── Groups ────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS groups (
        id          SERIAL PRIMARY KEY,
        name        VARCHAR(128) NOT NULL,
        description TEXT,
        privacy     VARCHAR(16)  NOT NULL DEFAULT 'public' CHECK (privacy IN ('public','private')),
        emoji       VARCHAR(8)   NOT NULL DEFAULT '👥',
        creator_id  INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );
    `);

    // ── Group Members ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS group_members (
        id        SERIAL PRIMARY KEY,
        group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role      VARCHAR(16) NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
        joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(group_id, user_id)
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_group_members_user  ON group_members(user_id);`);

    // ── Posts ─────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content    TEXT    NOT NULL DEFAULT '',
        group_id   INTEGER REFERENCES groups(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`DO $$ BEGIN ALTER TABLE posts ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE; EXCEPTION WHEN duplicate_column THEN NULL; END $$;`);

    // ── Post images ───────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS post_images (
        id      SERIAL PRIMARY KEY,
        post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        url     TEXT    NOT NULL,
        sort    INTEGER NOT NULL DEFAULT 0
      );
    `);

    // ── Likes ─────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS likes (
        id         SERIAL PRIMARY KEY,
        post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(post_id, user_id)
      );
    `);

    // ── Comments ──────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id         SERIAL PRIMARY KEY,
        post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        content    TEXT    NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // ── Messages ──────────────────────────────────────────────────────────────
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
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_user       ON posts(user_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_group      ON posts(group_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_posts_created    ON posts(created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_likes_post       ON likes(post_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_comments_post    ON comments(post_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_sender  ON messages(sender_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_recv    ON messages(receiver_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at ASC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_post_images_post ON post_images(post_id);`);

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
