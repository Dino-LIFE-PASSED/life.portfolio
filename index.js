const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { pool, initDb, createUser, getUserByUsername,
        getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
        getAllWallets, addWallet, deleteWallet, updateWalletBalance } = require('./db');

const app = express();
const PORT = 3000;

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session
app.use(session({
  store: new pgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days — stay logged in
    httpOnly: true,
  },
}));

// ─── Auth middleware ─────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function computeStats(assets) {
  const enriched = assets.map((a) => {
    const cost_basis = a.quantity * a.buy_price;
    const current_value =
      a.current_price != null ? a.quantity * a.current_price : null;
    const return_dollar =
      current_value != null ? current_value - cost_basis : null;
    const return_pct =
      a.current_price != null
        ? ((a.current_price - a.buy_price) / a.buy_price) * 100
        : null;
    return { ...a, cost_basis, current_value, return_dollar, return_pct };
  });

  const assetsWithPrice = enriched.filter((a) => a.current_value != null);
  const total_invested = enriched.reduce((s, a) => s + a.cost_basis, 0);
  const total_value = assetsWithPrice.reduce((s, a) => s + a.current_value, 0);
  const total_return_dollar = total_value - total_invested;
  const total_return_pct =
    total_invested > 0 ? (total_return_dollar / total_invested) * 100 : 0;

  const chartLabels = assetsWithPrice.map((a) => a.ticker.toUpperCase());
  const chartValues = assetsWithPrice.map((a) =>
    parseFloat(a.current_value.toFixed(2))
  );

  return {
    enriched,
    summary: {
      total_invested,
      total_value,
      total_return_dollar,
      total_return_pct,
      asset_count: assets.length,
    },
    chart: { labels: chartLabels, values: chartValues },
  };
}

// ─── Auth routes ─────────────────────────────────────────────────────────────

// GET /login
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.render('login', { error: null });
});

// POST /login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.render('login', { error: 'Username and password are required.' });

  const user = await getUserByUsername(username.trim().toLowerCase());
  if (!user) return res.render('login', { error: 'Invalid username or password.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.render('login', { error: 'Invalid username or password.' });

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect('/');
});

// GET /register
app.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/');
  res.render('register', { error: null });
});

// POST /register
app.post('/register', async (req, res) => {
  const { username, password, confirm } = req.body;

  if (!username || !password || !confirm)
    return res.render('register', { error: 'All fields are required.' });
  if (password !== confirm)
    return res.render('register', { error: 'Passwords do not match.' });
  if (password.length < 6)
    return res.render('register', { error: 'Password must be at least 6 characters.' });

  const existing = await getUserByUsername(username.trim().toLowerCase());
  if (existing)
    return res.render('register', { error: 'Username already taken.' });

  const passwordHash = await bcrypt.hash(password, 12);
  const user = await createUser(username.trim().toLowerCase(), passwordHash);

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect('/');
});

// POST /logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ─── Protected routes ────────────────────────────────────────────────────────

// GET / — Dashboard
app.get('/', requireAuth, async (req, res) => {
  const assets = await getAllAssets(req.session.userId);
  const { enriched, summary, chart } = computeStats(assets);
  const wallets = await getAllWallets(req.session.userId);
  res.render('index', {
    assets: enriched,
    summary,
    chart,
    wallets,
    username: req.session.username,
    error: req.query.error || null,
    success: req.query.success || null,
  });
});

// GET /add
app.get('/add', requireAuth, (_req, res) => {
  res.render('add', { error: null, formData: {} });
});

// POST /add
app.post('/add', requireAuth, async (req, res) => {
  const { name, ticker, asset_type, quantity, buy_price } = req.body;

  const errors = [];
  if (!name || name.trim() === '') errors.push('Asset name is required.');
  if (!ticker || ticker.trim() === '') errors.push('Ticker symbol is required.');
  if (!['stock', 'crypto', 'etf'].includes(asset_type)) errors.push('Invalid asset type.');
  if (!quantity || isNaN(parseFloat(quantity)) || parseFloat(quantity) <= 0)
    errors.push('Quantity must be a positive number.');
  if (!buy_price || isNaN(parseFloat(buy_price)) || parseFloat(buy_price) <= 0)
    errors.push('Buy price must be a positive number.');

  if (errors.length > 0)
    return res.render('add', { error: errors.join(' '), formData: req.body });

  try {
    await addAsset(req.session.userId, {
      name: name.trim(),
      ticker: ticker.trim().toUpperCase(),
      asset_type,
      quantity: parseFloat(quantity),
      buy_price: parseFloat(buy_price),
      buy_date: new Date().toISOString().split('T')[0],
    });
    res.redirect('/?success=Asset+added+successfully');
  } catch (err) {
    console.error('Error adding asset:', err);
    res.render('add', { error: 'Failed to save asset. Please try again.', formData: req.body });
  }
});

// GET /edit/:id
app.get('/edit/:id', requireAuth, async (req, res) => {
  const asset = await getAssetById(parseInt(req.params.id, 10), req.session.userId);
  if (!asset) return res.redirect('/?error=Asset+not+found');
  res.render('edit', { error: null, asset });
});

// POST /edit/:id
app.post('/edit/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, ticker, asset_type, quantity, buy_price } = req.body;

  const errors = [];
  if (!name || name.trim() === '') errors.push('Asset name is required.');
  if (!ticker || ticker.trim() === '') errors.push('Ticker symbol is required.');
  if (!['stock', 'crypto', 'etf'].includes(asset_type)) errors.push('Invalid asset type.');
  if (!quantity || isNaN(parseFloat(quantity)) || parseFloat(quantity) <= 0)
    errors.push('Quantity must be a positive number.');
  if (!buy_price || isNaN(parseFloat(buy_price)) || parseFloat(buy_price) <= 0)
    errors.push('Buy price must be a positive number.');

  if (errors.length > 0) {
    const asset = await getAssetById(id, req.session.userId);
    return res.render('edit', { error: errors.join(' '), asset: { ...asset, ...req.body, id } });
  }

  try {
    await updateAsset(id, req.session.userId, {
      name: name.trim(),
      ticker: ticker.trim().toUpperCase(),
      asset_type,
      quantity: parseFloat(quantity),
      buy_price: parseFloat(buy_price),
    });
    res.redirect('/?success=Asset+updated');
  } catch (err) {
    console.error('Error updating asset:', err);
    res.redirect('/?error=Failed+to+update+asset');
  }
});

// POST /delete/:id
app.post('/delete/:id', requireAuth, async (req, res) => {
  try {
    await deleteAsset(parseInt(req.params.id, 10), req.session.userId);
    res.redirect('/?success=Asset+deleted');
  } catch (err) {
    console.error('Error deleting asset:', err);
    res.redirect('/?error=Failed+to+delete+asset');
  }
});

// POST /wallet/add
app.post('/wallet/add', requireAuth, async (req, res) => {
  const { label, address } = req.body;
  if (!label || !address) return res.redirect('/?error=Label+and+address+required');
  try {
    await addWallet(req.session.userId, label.trim(), address.trim());
    res.redirect('/?success=Wallet+added');
  } catch (err) {
    const msg = err.message.includes('unique') || err.message.includes('UNIQUE')
      ? 'Address+already+tracked'
      : 'Failed+to+add+wallet';
    res.redirect('/?error=' + msg);
  }
});

// POST /wallet/delete/:id
app.post('/wallet/delete/:id', requireAuth, async (req, res) => {
  await deleteWallet(parseInt(req.params.id, 10), req.session.userId);
  res.redirect('/?success=Wallet+removed');
});

// GET /api/wallets
app.get('/api/wallets', requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const wallets = await getAllWallets(req.session.userId);
  if (wallets.length === 0) return res.json([]);

  let btcUsd = null;
  try {
    const r = await fetch('https://mempool.space/api/v1/prices');
    if (r.ok) btcUsd = (await r.json()).USD;
  } catch (_) {}

  const now = new Date().toISOString();
  const results = await Promise.all(wallets.map(async (w) => {
    try {
      const r = await fetch(`https://mempool.space/api/address/${w.address}`);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const d = await r.json();
      const btc = (d.chain_stats.funded_txo_sum - d.chain_stats.spent_txo_sum) / 1e8;
      const unconfirmed = (d.mempool_stats.funded_txo_sum - d.mempool_stats.spent_txo_sum) / 1e8;
      const usd = btcUsd != null ? btc * btcUsd : null;
      await updateWalletBalance(w.id, btc, unconfirmed, usd, now);
      return { id: w.id, label: w.label, address: w.address, btc, unconfirmed, usd, updated: now };
    } catch (err) {
      console.error(`Wallet fetch failed for ${w.address}:`, err.message);
      return { id: w.id, label: w.label, address: w.address,
               btc: w.btc_balance, unconfirmed: w.btc_unconfirmed,
               usd: w.usd_value, updated: w.last_updated };
    }
  }));

  res.json(results);
});

// Shared price fetcher
async function fetchPrice(ticker) {
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ticker)}?interval=1d&range=1d`;
  const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  const price = data.chart.result?.[0]?.meta?.regularMarketPrice;
  if (price == null) throw new Error('No price in response');
  return price;
}

// GET /api/prices
app.get('/api/prices', requireAuth, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const assets = await getAllAssets(req.session.userId);
  const now = new Date().toISOString();
  const results = {};

  await Promise.all(assets.map(async (asset) => {
    try {
      const price = await fetchPrice(asset.ticker);
      await updatePrice(asset.id, price, now);
      results[asset.id] = { price, updated: now };
    } catch (err) {
      console.error(`Price fetch failed for ${asset.ticker}:`, err.message);
      results[asset.id] = asset.current_price != null
        ? { price: asset.current_price, updated: asset.last_updated }
        : null;
    }
  }));

  res.json(results);
});

// POST /refresh
app.post('/refresh', requireAuth, async (req, res) => {
  const assets = await getAllAssets(req.session.userId);
  if (assets.length === 0) return res.redirect('/?error=No+assets+to+refresh');

  const now = new Date().toISOString();
  const failed = [];

  for (const asset of assets) {
    try {
      const price = await fetchPrice(asset.ticker);
      await updatePrice(asset.id, price, now);
    } catch (err) {
      console.error(`Failed to fetch price for ${asset.ticker}:`, err.message);
      failed.push(asset.ticker);
    }
  }

  if (failed.length > 0)
    return res.redirect(`/?error=Could+not+fetch+prices+for:+${encodeURIComponent(failed.join(', '))}`);

  res.redirect('/?success=Prices+refreshed+successfully');
});

// ─── Start ───────────────────────────────────────────────────────────────────

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Portfolio tracker running at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
