const express = require('express');
const path = require('path');
const { getAllAssets, getAssetById, addAsset, updateAsset, deleteAsset, updatePrice,
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

// ─── Routes ─────────────────────────────────────────────────────────────────

// GET / — Dashboard
app.get('/', (req, res) => {
  const assets = getAllAssets();
  const { enriched, summary, chart } = computeStats(assets);
  const wallets = getAllWallets();
  res.render('index', {
    assets: enriched,
    summary,
    chart,
    wallets,
    error: req.query.error || null,
    success: req.query.success || null,
  });
});

// GET /add — Add asset form
app.get('/add', (req, res) => {
  res.render('add', { error: null, formData: {} });
});

// POST /add — Insert new asset
app.post('/add', (req, res) => {
  const { name, ticker, asset_type, quantity, buy_price } = req.body;

  const errors = [];
  if (!name || name.trim() === '') errors.push('Asset name is required.');
  if (!ticker || ticker.trim() === '') errors.push('Ticker symbol is required.');
  if (!['stock', 'crypto', 'etf'].includes(asset_type))
    errors.push('Invalid asset type.');
  if (!quantity || isNaN(parseFloat(quantity)) || parseFloat(quantity) <= 0)
    errors.push('Quantity must be a positive number.');
  if (!buy_price || isNaN(parseFloat(buy_price)) || parseFloat(buy_price) <= 0)
    errors.push('Buy price must be a positive number.');

  if (errors.length > 0) {
    return res.render('add', { error: errors.join(' '), formData: req.body });
  }

  try {
    addAsset({
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
    res.render('add', {
      error: 'Failed to save asset. Please try again.',
      formData: req.body,
    });
  }
});

// GET /edit/:id — Edit asset form
app.get('/edit/:id', (req, res) => {
  const asset = getAssetById(parseInt(req.params.id, 10));
  if (!asset) return res.redirect('/?error=Asset+not+found');
  res.render('edit', { error: null, asset });
});

// POST /edit/:id — Save edited asset
app.post('/edit/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, ticker, asset_type, quantity, buy_price } = req.body;

  const errors = [];
  if (!name || name.trim() === '') errors.push('Asset name is required.');
  if (!ticker || ticker.trim() === '') errors.push('Ticker symbol is required.');
  if (!['stock', 'crypto', 'etf'].includes(asset_type))
    errors.push('Invalid asset type.');
  if (!quantity || isNaN(parseFloat(quantity)) || parseFloat(quantity) <= 0)
    errors.push('Quantity must be a positive number.');
  if (!buy_price || isNaN(parseFloat(buy_price)) || parseFloat(buy_price) <= 0)
    errors.push('Buy price must be a positive number.');

  if (errors.length > 0) {
    const asset = getAssetById(id);
    return res.render('edit', { error: errors.join(' '), asset: { ...asset, ...req.body, id } });
  }

  try {
    updateAsset(id, {
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

// POST /delete/:id — Remove an asset
app.post('/delete/:id', (req, res) => {
  const { id } = req.params;
  try {
    deleteAsset(parseInt(id, 10));
    res.redirect('/?success=Asset+deleted');
  } catch (err) {
    console.error('Error deleting asset:', err);
    res.redirect('/?error=Failed+to+delete+asset');
  }
});

// POST /wallet/add
app.post('/wallet/add', (req, res) => {
  const { label, address } = req.body;
  if (!label || !address) return res.redirect('/?error=Label+and+address+required');
  try {
    addWallet(label.trim(), address.trim());
    res.redirect('/?success=Wallet+added');
  } catch (err) {
    const msg = err.message.includes('UNIQUE') ? 'Address+already+tracked' : 'Failed+to+add+wallet';
    res.redirect('/?error=' + msg);
  }
});

// POST /wallet/delete/:id
app.post('/wallet/delete/:id', (req, res) => {
  deleteWallet(parseInt(req.params.id, 10));
  res.redirect('/?success=Wallet+removed');
});

// GET /api/wallets — fetch balances from mempool.space
app.get('/api/wallets', async (_req, res) => {
  res.set('Cache-Control', 'no-store');
  const wallets = getAllWallets();
  if (wallets.length === 0) return res.json([]);

  // Get BTC price from mempool
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
      updateWalletBalance(w.id, btc, unconfirmed, usd, now);
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

// GET /api/prices — Return latest prices as JSON (for live polling)
app.get('/api/prices', async (_req, res) => {
  res.set('Cache-Control', 'no-store');
  const assets = getAllAssets();
  const now = new Date().toISOString();
  const results = {};

  await Promise.all(assets.map(async (asset) => {
    try {
      const price = await fetchPrice(asset.ticker);
      updatePrice(asset.id, price, now);
      results[asset.id] = { price, updated: now };
    } catch (err) {
      console.error(`Price fetch failed for ${asset.ticker}:`, err.message);
      const existing = assets.find(a => a.id === asset.id);
      results[asset.id] = existing?.current_price != null
        ? { price: existing.current_price, updated: existing.last_updated }
        : null;
    }
  }));

  res.json(results);
});

// POST /refresh — Fetch latest prices from Yahoo Finance
app.post('/refresh', async (_req, res) => {
  const assets = getAllAssets();

  if (assets.length === 0) {
    return res.redirect('/?error=No+assets+to+refresh');
  }

  const now = new Date().toISOString();
  const failed = [];

  for (const asset of assets) {
    try {
      const price = await fetchPrice(asset.ticker);
      updatePrice(asset.id, price, now);
    } catch (err) {
      console.error(`Failed to fetch price for ${asset.ticker}:`, err.message);
      failed.push(asset.ticker);
    }
  }

  if (failed.length > 0) {
    return res.redirect(
      `/?error=Could+not+fetch+prices+for:+${encodeURIComponent(failed.join(', '))}`
    );
  }

  res.redirect('/?success=Prices+refreshed+successfully');
});

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Portfolio tracker running at http://localhost:${PORT}`);
});
