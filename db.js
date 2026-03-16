const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'portfolio.db'));

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    btc_balance REAL,
    btc_unconfirmed REAL,
    usd_value REAL,
    last_updated TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

function getAllAssets() {
  return db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
}

function addAsset(data) {
  const stmt = db.prepare(`
    INSERT INTO assets (name, ticker, asset_type, quantity, buy_price, buy_date)
    VALUES (@name, @ticker, @asset_type, @quantity, @buy_price, @buy_date)
  `);
  return stmt.run(data);
}

function deleteAsset(id) {
  return db.prepare('DELETE FROM assets WHERE id = ?').run(id);
}

function getAssetById(id) {
  return db.prepare('SELECT * FROM assets WHERE id = ?').get(id);
}

function updateAsset(id, data) {
  return db.prepare(`
    UPDATE assets SET name = @name, ticker = @ticker, asset_type = @asset_type,
    quantity = @quantity, buy_price = @buy_price WHERE id = @id
  `).run({ ...data, id });
}

function updatePrice(id, price, lastUpdated) {
  return db.prepare(
    'UPDATE assets SET current_price = ?, last_updated = ? WHERE id = ?'
  ).run(price, lastUpdated, id);
}

function getAllWallets() {
  return db.prepare('SELECT * FROM wallets ORDER BY created_at ASC').all();
}

function addWallet(label, address) {
  return db.prepare('INSERT INTO wallets (label, address) VALUES (?, ?)').run(label, address);
}

function deleteWallet(id) {
  return db.prepare('DELETE FROM wallets WHERE id = ?').run(id);
}

function updateWalletBalance(id, btc_balance, btc_unconfirmed, usd_value, last_updated) {
  return db.prepare(
    'UPDATE wallets SET btc_balance=?, btc_unconfirmed=?, usd_value=?, last_updated=? WHERE id=?'
  ).run(btc_balance, btc_unconfirmed, usd_value, last_updated, id);
}

module.exports = {
  getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
  getAllWallets, addWallet, deleteWallet, updateWalletBalance,
};
