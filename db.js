const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Initialize schema
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
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
      label TEXT NOT NULL,
      address TEXT NOT NULL UNIQUE,
      btc_balance REAL,
      btc_unconfirmed REAL,
      usd_value REAL,
      last_updated TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

async function getAllAssets() {
  const { rows } = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
  return rows;
}

async function getAssetById(id) {
  const { rows } = await pool.query('SELECT * FROM assets WHERE id = $1', [id]);
  return rows[0] || null;
}

async function addAsset(data) {
  await pool.query(
    `INSERT INTO assets (name, ticker, asset_type, quantity, buy_price, buy_date)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [data.name, data.ticker, data.asset_type, data.quantity, data.buy_price, data.buy_date]
  );
}

async function updateAsset(id, data) {
  await pool.query(
    `UPDATE assets SET name=$1, ticker=$2, asset_type=$3, quantity=$4, buy_price=$5 WHERE id=$6`,
    [data.name, data.ticker, data.asset_type, data.quantity, data.buy_price, id]
  );
}

async function deleteAsset(id) {
  await pool.query('DELETE FROM assets WHERE id = $1', [id]);
}

async function updatePrice(id, price, lastUpdated) {
  await pool.query(
    'UPDATE assets SET current_price=$1, last_updated=$2 WHERE id=$3',
    [price, lastUpdated, id]
  );
}

async function getAllWallets() {
  const { rows } = await pool.query('SELECT * FROM wallets ORDER BY created_at ASC');
  return rows;
}

async function addWallet(label, address) {
  await pool.query(
    'INSERT INTO wallets (label, address) VALUES ($1, $2)',
    [label, address]
  );
}

async function deleteWallet(id) {
  await pool.query('DELETE FROM wallets WHERE id = $1', [id]);
}

async function updateWalletBalance(id, btc_balance, btc_unconfirmed, usd_value, last_updated) {
  await pool.query(
    'UPDATE wallets SET btc_balance=$1, btc_unconfirmed=$2, usd_value=$3, last_updated=$4 WHERE id=$5',
    [btc_balance, btc_unconfirmed, usd_value, last_updated, id]
  );
}

module.exports = {
  initDb,
  getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
  getAllWallets, addWallet, deleteWallet, updateWalletBalance,
};
