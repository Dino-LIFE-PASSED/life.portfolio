const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const HDKey = require('hdkey');
const bs58check = require('bs58check');
const { bech32 } = require('bech32');
const { pool, initDb, createUser, getUserByUsername, updateUserProfile,
        getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
        getAllWallets, addWallet, deleteWallet, updateWalletBalance } = require('./db');

// ─── xPub address derivation ─────────────────────────────────────────────────

function hash160(buf) {
  const sha = crypto.createHash('sha256').update(buf).digest();
  return crypto.createHash('ripemd160').update(sha).digest();
}

function xpubToAddress(pubKey, type) {
  const h160 = hash160(pubKey);
  if (type === 'zpub') {
    // P2WPKH native segwit (bc1q...)
    const words = bech32.toWords(h160);
    return bech32.encode('bc', [0x00, ...words]);
  } else if (type === 'ypub') {
    // P2SH-P2WPKH wrapped segwit (3...)
    const redeemScript = Buffer.concat([Buffer.from([0x00, 0x14]), h160]);
    const scriptHash = hash160(redeemScript);
    return bs58check.encode(Buffer.concat([Buffer.from([0x05]), scriptHash]));
  } else {
    // P2PKH legacy (1...)
    return bs58check.encode(Buffer.concat([Buffer.from([0x00]), h160]));
  }
}

function normalizeXpub(extKey) {
  // Convert ypub/zpub to xpub version bytes for HDKey parsing
  const raw = bs58check.decode(extKey);
  const buf = Buffer.from(raw);
  buf.writeUInt32BE(0x0488b21e, 0); // standard xpub version
  return bs58check.encode(buf);
}

function isXpub(str) {
  return /^[xyz]pub/.test(str);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function scanXpub(xpubStr) {
  const type = xpubStr.slice(0, 4); // xpub, ypub, zpub
  const normalized = (type === 'xpub') ? xpubStr : normalizeXpub(xpubStr);
  const master = HDKey.fromExtendedKey(normalized);
  const external = master.derive('m/0'); // external chain

  const GAP_LIMIT = 20;
  let gap = 0;
  let index = 0;
  let totalSats = 0;
  let retries = 0;

  while (gap < GAP_LIMIT) {
    const child = external.deriveChild(index);
    const address = xpubToAddress(child.publicKey, type);

    try {
      const r = await fetch(`https://blockstream.info/api/address/${address}`);
      if (r.status === 429) {
        // Rate limited — wait longer and retry same index
        await sleep(2000);
        continue;
      }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      const txCount = d.chain_stats.tx_count + d.mempool_stats.tx_count;
      const balance = d.chain_stats.funded_txo_sum - d.chain_stats.spent_txo_sum
                    + d.mempool_stats.funded_txo_sum - d.mempool_stats.spent_txo_sum;
      if (txCount === 0) {
        gap++;
      } else {
        gap = 0;
        totalSats += balance;
      }
      retries = 0;
    } catch (err) {
      console.error(`xpub scan error at index ${index}:`, err.message);
      retries++;
      if (retries >= 3) {
        // Too many failures — give up scanning, return what we have
        break;
      }
      await sleep(1000);
      continue; // retry same index
    }
    index++;
    await sleep(150); // 150ms between requests to avoid rate limiting
  }

  return totalSats / 1e8; // satoshis → BTC
}

const app = express();
const PORT = 3000;

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
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
  req.session.hasProfileImage = !!user.profile_image_url;
  req.session.hasBgGif = !!user.bg_gif_url;
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
  req.session.hasProfileImage = false;
  req.session.hasBgGif = false;
  res.redirect('/');
});

// POST /profile
app.post('/profile', requireAuth, async (req, res) => {
  const { profile_image_url, bg_gif_url } = req.body;
  console.log(`[profile] user=${req.session.userId} profileLen=${(profile_image_url||'').length} bgLen=${(bg_gif_url||'').length}`);
  const updated = await updateUserProfile(req.session.userId, profile_image_url, bg_gif_url);
  console.log(`[profile] saved profileLen=${(updated.profile_image_url||'').length} bgLen=${(updated.bg_gif_url||'').length}`);
  req.session.hasProfileImage = !!updated.profile_image_url;
  req.session.hasBgGif = !!updated.bg_gif_url;
  // JSON clients (fetch) get a JSON response; form clients get a redirect
  if (req.is('application/json')) return res.json({ ok: true });
  res.redirect('/?success=Profile+updated');
});

// GET /api/profile/avatar — serve profile image as binary
app.get('/api/profile/avatar', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT profile_image_url FROM users WHERE id=$1', [req.session.userId]);
  const url = rows[0]?.profile_image_url;
  if (!url) return res.status(404).end();
  if (url.startsWith('data:')) {
    const [meta, b64] = url.split(',');
    const mimeMatch = meta.match(/data:([^;]+)/);
    const mime = mimeMatch ? mimeMatch[1] : 'image/gif';
    const buf = Buffer.from(b64, 'base64');
    res.set('Content-Type', mime);
    res.set('Cache-Control', 'no-store');
    return res.send(buf);
  }
  res.redirect(url);
});

// GET /api/profile/bg — serve background gif as binary
app.get('/api/profile/bg', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT bg_gif_url FROM users WHERE id=$1', [req.session.userId]);
  const url = rows[0]?.bg_gif_url;
  if (!url) return res.status(404).end();
  if (url.startsWith('data:')) {
    const [meta, b64] = url.split(',');
    const mimeMatch = meta.match(/data:([^;]+)/);
    const mime = mimeMatch ? mimeMatch[1] : 'image/gif';
    const buf = Buffer.from(b64, 'base64');
    res.set('Content-Type', mime);
    res.set('Cache-Control', 'no-store');
    return res.send(buf);
  }
  res.redirect(url);
});

// GET /api/debug/image-sizes — check stored image byte sizes
app.get('/api/debug/image-sizes', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT profile_image_url, bg_gif_url FROM users WHERE id=$1', [req.session.userId]);
  const row = rows[0] || {};
  const info = {
    profile: row.profile_image_url
      ? { bytes: Buffer.byteLength(row.profile_image_url, 'utf8'), isDataUrl: row.profile_image_url.startsWith('data:') }
      : null,
    bg: row.bg_gif_url
      ? { bytes: Buffer.byteLength(row.bg_gif_url, 'utf8'), isDataUrl: row.bg_gif_url.startsWith('data:') }
      : null,
  };
  res.json(info);
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

  // Add wallets with known USD value to the pie chart
  wallets.forEach(w => {
    if (w.usd_value != null && w.usd_value > 0) {
      chart.labels.push(w.label);
      chart.values.push(parseFloat(w.usd_value.toFixed(2)));
    }
  });

  res.render('index', {
    assets: enriched,
    summary,
    chart,
    wallets,
    username: req.session.username,
    hasProfileImage: !!req.session.hasProfileImage,
    hasBgGif: !!req.session.hasBgGif,
    error: req.query.error || null,
    success: req.query.success || null,
  });
});

// GET /add
app.get('/add', requireAuth, (req, res) => {
  res.render('add', { error: null, formData: {}, username: req.session.username, hasProfileImage: !!req.session.hasProfileImage, hasBgGif: !!req.session.hasBgGif });
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
  res.render('edit', { error: null, asset, username: req.session.username, hasProfileImage: !!req.session.hasProfileImage, hasBgGif: !!req.session.hasBgGif });
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
  const input = address.trim();
  if (!isXpub(input) && !input.match(/^(1|3|bc1)[a-zA-Z0-9]{20,}/)) {
    return res.redirect('/?error=Invalid+Bitcoin+address+or+xPub');
  }
  try {
    await addWallet(req.session.userId, label.trim(), input);
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
    const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
    if (r.ok) btcUsd = (await r.json()).bitcoin.usd;
  } catch (_) {}

  const now = new Date().toISOString();
  const results = await Promise.all(wallets.map(async (w) => {
    try {
      let btc, unconfirmed;

      if (isXpub(w.address)) {
        // xpub/ypub/zpub: scan all derived addresses
        btc = await scanXpub(w.address);
        unconfirmed = 0;
      } else {
        // Single address
        const r = await fetch(`https://blockstream.info/api/address/${w.address}`);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        btc = (d.chain_stats.funded_txo_sum - d.chain_stats.spent_txo_sum) / 1e8;
        unconfirmed = (d.mempool_stats.funded_txo_sum - d.mempool_stats.spent_txo_sum) / 1e8;
      }

      const usd = btcUsd != null ? btc * btcUsd : null;
      await updateWalletBalance(w.id, btc, unconfirmed, usd, now);
      return { id: w.id, label: w.label, address: w.address, btc, unconfirmed, usd };
    } catch (err) {
      console.error(`Wallet fetch failed for ${w.address}:`, err.message);
      return { id: w.id, label: w.label, address: w.address,
               btc: w.btc_balance, unconfirmed: w.btc_unconfirmed, usd: w.usd_value };
    }
  }));

  res.json(results);
});

// GET /api/resolve-image — extract direct image URL from any webpage
app.get('/api/resolve-image', requireAuth, async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing url parameter' });

  // If it already looks like a direct image, return as-is
  if (/\.(gif|jpg|jpeg|png|webp|svg)(\?.*)?$/i.test(url) ||
      /^https?:\/\/media\.tenor\.com\//i.test(url) ||
      /^https?:\/\/i\.giphy\.com\//i.test(url) ||
      /^https?:\/\/media\d*\.giphy\.com\//i.test(url)) {
    return res.json({ resolvedUrl: url });
  }

  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; bot)' },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const html = await r.text();

    // Try og:image first
    const ogMatch = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
                 || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    if (ogMatch) return res.json({ resolvedUrl: ogMatch[1] });

    // Try twitter:image
    const twMatch = html.match(/<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']/i)
                 || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["']/i);
    if (twMatch) return res.json({ resolvedUrl: twMatch[1] });

    // Fall back to original URL
    res.json({ resolvedUrl: url });
  } catch (err) {
    console.error('resolve-image error:', err.message);
    res.json({ resolvedUrl: url }); // fall back silently
  }
});

// GET /api/rates — USD to THB exchange rate
app.get('/api/rates', requireAuth, async (_req, res) => {
  try {
    const r = await fetch('https://api.frankfurter.app/latest?from=USD&to=THB');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    res.json({ usdToThb: data.rates.THB });
  } catch (err) {
    console.error('Rate fetch failed:', err.message);
    res.status(502).json({ error: 'Could not fetch exchange rate' });
  }
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

    // Reclaim space from overwritten base64 image blobs every hour
    async function vacuumImages() {
      try {
        await pool.query('VACUUM ANALYZE users');
        console.log('[vacuum] users table cleaned');
      } catch (err) {
        console.error('[vacuum] error:', err.message);
      }
    }
    vacuumImages(); // run once on startup to clear any existing bloat
    setInterval(vacuumImages, 60 * 60 * 1000); // then every hour
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
