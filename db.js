const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initDb() {
  // Create tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      ticker TEXT NOT NULL,
      asset_type TEXT NOT NULL DEFAULT 'stock',
      quantity REAL NOT NULL,
      buy_price REAL NOT NULL,
      buy_date TEXT NOT NULL,
      current_price REAL,
      last_updated TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      address TEXT NOT NULL,
      btc_balance REAL,
      btc_unconfirmed REAL,
      usd_value REAL,
      last_updated TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Migrate existing tables
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_image_url TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bg_gif_url TEXT;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
    ALTER TABLE wallets ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
    ALTER TABLE wallets DROP CONSTRAINT IF EXISTS wallets_address_key;
  `);

  // Add unique constraint per user if not exists
  await pool.query(`
    DO $$ BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'wallets_user_id_address_key'
      ) THEN
        ALTER TABLE wallets ADD CONSTRAINT wallets_user_id_address_key UNIQUE (user_id, address);
      END IF;
    END $$;
  `);
}

// ─── Users ───────────────────────────────────────────────────────────────────

async function createUser(username, passwordHash) {
  const { rows } = await pool.query(
    'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
    [username, passwordHash]
  );
  return rows[0];
}

async function getUserByUsername(username) {
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );
  return rows[0] || null;
}

async function updateUserProfile(id, profileImageUrl, bgGifUrl) {
  const { rows } = await pool.query(
    'UPDATE users SET profile_image_url=$1, bg_gif_url=$2 WHERE id=$3 RETURNING profile_image_url, bg_gif_url',
    [profileImageUrl || null, bgGifUrl || null, id]
  );
  return rows[0];
}

// ─── Assets ──────────────────────────────────────────────────────────────────

async function getAllAssets(userId) {
  const { rows } = await pool.query(
    'SELECT * FROM assets WHERE user_id = $1 ORDER BY created_at DESC',
    [userId]
  );
  return rows;
}

async function getAssetById(id, userId) {
  const { rows } = await pool.query(
    'SELECT * FROM assets WHERE id = $1 AND user_id = $2',
    [id, userId]
  );
  return rows[0] || null;
}

async function addAsset(userId, data) {
  await pool.query(
    `INSERT INTO assets (user_id, name, ticker, asset_type, quantity, buy_price, buy_date)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [userId, data.name, data.ticker, data.asset_type, data.quantity, data.buy_price, data.buy_date]
  );
}

async function updateAsset(id, userId, data) {
  await pool.query(
    `UPDATE assets SET name=$1, ticker=$2, asset_type=$3, quantity=$4, buy_price=$5
     WHERE id=$6 AND user_id=$7`,
    [data.name, data.ticker, data.asset_type, data.quantity, data.buy_price, id, userId]
  );
}

async function deleteAsset(id, userId) {
  await pool.query('DELETE FROM assets WHERE id = $1 AND user_id = $2', [id, userId]);
}

async function updatePrice(id, price, lastUpdated) {
  await pool.query(
    'UPDATE assets SET current_price=$1, last_updated=$2 WHERE id=$3',
    [price, lastUpdated, id]
  );
}

// ─── Wallets ─────────────────────────────────────────────────────────────────

async function getAllWallets(userId) {
  const { rows } = await pool.query(
    'SELECT * FROM wallets WHERE user_id = $1 ORDER BY created_at ASC',
    [userId]
  );
  return rows;
}

async function addWallet(userId, label, address) {
  await pool.query(
    'INSERT INTO wallets (user_id, label, address) VALUES ($1, $2, $3)',
    [userId, label, address]
  );
}

async function deleteWallet(id, userId) {
  await pool.query('DELETE FROM wallets WHERE id = $1 AND user_id = $2', [id, userId]);
}

async function updateWalletBalance(id, btc_balance, btc_unconfirmed, usd_value, last_updated) {
  await pool.query(
    'UPDATE wallets SET btc_balance=$1, btc_unconfirmed=$2, usd_value=$3, last_updated=$4 WHERE id=$5',
    [btc_balance, btc_unconfirmed, usd_value, last_updated, id]
  );
}

module.exports = {
  pool,
  initDb,
  createUser, getUserByUsername, updateUserProfile,
  getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
  getAllWallets, addWallet, deleteWallet, updateWalletBalance,
};
