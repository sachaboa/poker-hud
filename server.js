const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pokerHUD_secret_2024_change_me';

// ── Database setup ──────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS players (
      id TEXT PRIMARY KEY,
      pseudo TEXT DEFAULT '',
      a INTEGER DEFAULT 0,
      c INTEGER DEFAULT 0,
      tags TEXT DEFAULT '[]',
      reads TEXT DEFAULT '[]',
      notes TEXT DEFAULT '[]',
      sz TEXT DEFAULT '{}',
      src TEXT DEFAULT 'KK',
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      updated_by TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS sessions_table (
      id SERIAL PRIMARY KEY,
      "user" TEXT NOT NULL,
      seats TEXT DEFAULT '[null,null,null,null,null,null]',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id SERIAL PRIMARY KEY,
      player_id TEXT NOT NULL,
      note TEXT NOT NULL,
      conf INTEGER DEFAULT 1,
      ts TEXT,
      by TEXT,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Tables créées / vérifiées');
}

// ── Seed users if not exist ─────────────────────────────────────────────────
async function seedUsers() {
  const seedList = [
    { username: 'sacha', password: '@1234567' },
    { username: 'iaco',  password: 'changeme' },
  ];
  for (const u of seedList) {
    const { rows } = await pool.query('SELECT id FROM users WHERE username = $1', [u.username]);
    if (rows.length === 0) {
      const hash = await bcrypt.hash(u.password, 10);
      await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [u.username, hash]);
      console.log(`User created: ${u.username}`);
    }
  }
}

// ── Seed player database ────────────────────────────────────────────────────
async function seedPlayers() {
  const { rows } = await pool.query('SELECT COUNT(*) AS n FROM players');
  if (parseInt(rows[0].n) === 0) {
    console.log('Seeding player database...');
    const INIT_PLAYERS = require('./init_players.json');
    for (const [id, p] of Object.entries(INIT_PLAYERS)) {
      await pool.query(
        `INSERT INTO players (id, pseudo, a, c, tags, reads, notes, sz, src)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (id) DO NOTHING`,
        [
          id,
          p.p || '',
          p.a || 0,
          p.c || 0,
          JSON.stringify(p.t || []),
          JSON.stringify(p.r || []),
          JSON.stringify(p.n || []),
          JSON.stringify(p.sz || {}),
          p.src || 'KK',
        ]
      );
    }
    console.log(`Seeded ${Object.keys(INIT_PLAYERS).length} players`);
  }
}

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ── Auth routes ─────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });

  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase()]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Utilisateur inconnu' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect' });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.post('/api/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [req.user.username]);
  const user = rows[0];
  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [hash, req.user.username]);
  res.json({ ok: true });
});

// ── Player routes ───────────────────────────────────────────────────────────
app.get('/api/players', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM players');
  const result = {};
  for (const row of rows) {
    result[row.id] = {
      p: row.pseudo,
      a: row.a,
      c: row.c,
      t: JSON.parse(row.tags),
      r: JSON.parse(row.reads),
      n: JSON.parse(row.notes),
      sz: JSON.parse(row.sz),
      src: row.src,
      updated_at: row.updated_at,
      updated_by: row.updated_by,
    };
  }
  res.json(result);
});

app.get('/api/players/:id', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM players WHERE id = $1', [req.params.id]);
  const row = rows[0];
  if (!row) return res.status(404).json({ error: 'Joueur non trouvé' });
  res.json({
    p: row.pseudo, a: row.a, c: row.c,
    t: JSON.parse(row.tags), r: JSON.parse(row.reads),
    n: JSON.parse(row.notes), sz: JSON.parse(row.sz),
    src: row.src, updated_at: row.updated_at, updated_by: row.updated_by,
  });
});

app.put('/api/players/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const p = req.body;
  const { rows } = await pool.query('SELECT id FROM players WHERE id = $1', [id]);
  if (rows.length > 0) {
    await pool.query(
      `UPDATE players SET pseudo=$1, a=$2, c=$3, tags=$4, reads=$5, notes=$6, sz=$7, src=$8,
       updated_at=NOW(), updated_by=$9 WHERE id=$10`,
      [p.p||'', p.a||0, p.c||0, JSON.stringify(p.t||[]),
       JSON.stringify(p.r||[]), JSON.stringify(p.n||[]),
       JSON.stringify(p.sz||{}), p.src||'KK', req.user.username, id]
    );
  } else {
    await pool.query(
      `INSERT INTO players (id, pseudo, a, c, tags, reads, notes, sz, src, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [id, p.p||'', p.a||0, p.c||0, JSON.stringify(p.t||[]),
       JSON.stringify(p.r||[]), JSON.stringify(p.n||[]),
       JSON.stringify(p.sz||{}), p.src||'KK', req.user.username]
    );
  }
  res.json({ ok: true });
});

app.post('/api/players/:id/note', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { text, conf } = req.body;
  if (!text) return res.status(400).json({ error: 'Note vide' });

  let { rows } = await pool.query('SELECT * FROM players WHERE id = $1', [id]);
  if (rows.length === 0) {
    await pool.query(
      'INSERT INTO players (id, notes, updated_by) VALUES ($1, $2, $3)',
      [id, JSON.stringify([]), req.user.username]
    );
    ({ rows } = await pool.query('SELECT * FROM players WHERE id = $1', [id]));
  }
  const row = rows[0];
  const notes = JSON.parse(row.notes || '[]');
  notes.push({
    t: text, conf: conf || 1,
    ts: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
    by: req.user.username,
  });
  await pool.query(
    'UPDATE players SET notes=$1, updated_at=NOW(), updated_by=$2 WHERE id=$3',
    [JSON.stringify(notes), req.user.username, id]
  );
  res.json({ ok: true });
});

// ── Reviews ─────────────────────────────────────────────────────────────────
app.get('/api/reviews', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM reviews WHERE status='pending' ORDER BY created_at DESC"
  );
  res.json(rows);
});

app.post('/api/reviews', authMiddleware, async (req, res) => {
  const { player_id, note, conf } = req.body;
  await pool.query(
    'INSERT INTO reviews (player_id, note, conf, ts, by) VALUES ($1, $2, $3, $4, $5)',
    [
      player_id, note, conf || 1,
      new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
      req.user.username,
    ]
  );
  res.json({ ok: true });
});

app.patch('/api/reviews/:id', authMiddleware, async (req, res) => {
  const { status } = req.body;
  await pool.query('UPDATE reviews SET status=$1 WHERE id=$2', [status, req.params.id]);
  res.json({ ok: true });
});

// ── AI Analysis route ───────────────────────────────────────────────────────
app.post('/api/analyze', authMiddleware, async (req, res) => {
  const { player_id, note } = req.body;
  const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_KEY) return res.json({ analysis: 'Clé API Anthropic non configurée.' });

  const { rows } = await pool.query('SELECT * FROM players WHERE id = $1', [player_id]);
  const player = rows[0];
  const existingReads = player ? JSON.parse(player.reads || '[]') : [];
  const readsSummary = existingReads.slice(0, 10).map(r =>
    typeof r === 'string' ? r : r.t
  ).join(' / ');

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 300,
        messages: [{
          role: 'user',
          content: `Tu es un assistant d'analyse poker. Voici les reads existants sur le joueur ${player_id}: "${readsSummary}". Nouvelle note brute prise en session: "${note}". En 2-3 phrases max, dis si cette note: 1) confirme un read existant, 2) contredit un read existant, ou 3) apporte une nouvelle information. Réponds en français, de manière concise et directe.`,
        }],
      }),
    });
    const data = await response.json();
    res.json({ analysis: data.content?.[0]?.text || 'Analyse indisponible.' });
  } catch (e) {
    res.json({ analysis: "Erreur lors de l'analyse." });
  }
});

// ── Catch-all → index.html ───────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ────────────────────────────────────────────────────────────────────
initDB()
  .then(seedUsers)
  .then(seedPlayers)
  .then(() => {
    app.listen(PORT, () => console.log(`Poker HUD running on port ${PORT}`));
  })
  .catch(err => {
    console.error('Startup error:', err);
    process.exit(1);
  });
