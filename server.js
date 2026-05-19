const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pokerHUD_secret_2024_change_me';

// ── Database setup ──────────────────────────────────────────────────────────
const db = new Database('poker.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS sessions_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    seats TEXT DEFAULT '[null,null,null,null,null,null]',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ── Seed users if not exist ─────────────────────────────────────────────────
const seedUsers = [
  { username: 'sacha', password: '@1234567' },
  { username: 'iaco',  password: 'changeme' },
];

for (const u of seedUsers) {
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
  if (!exists) {
    const hash = bcrypt.hashSync(u.password, 10);
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(u.username, hash);
    console.log(`User created: ${u.username}`);
  }
}

// ── Seed player database ────────────────────────────────────────────────────
// Only seed if table is empty
const playerCount = db.prepare('SELECT COUNT(*) as n FROM players').get();
if (playerCount.n === 0) {
  console.log('Seeding player database...');
  const INIT_PLAYERS = require('./init_players.json');
  const insert = db.prepare(`
    INSERT OR IGNORE INTO players (id, pseudo, a, c, tags, reads, notes, sz, src)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertMany = db.transaction((players) => {
    for (const [id, p] of Object.entries(players)) {
      insert.run(
        id,
        p.p || '',
        p.a || 0,
        p.c || 0,
        JSON.stringify(p.t || []),
        JSON.stringify(p.r || []),
        JSON.stringify(p.n || []),
        JSON.stringify(p.sz || {}),
        p.src || 'KK'
      );
    }
  });
  insertMany(INIT_PLAYERS);
  console.log(`Seeded ${Object.keys(INIT_PLAYERS).length} players`);
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
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Utilisateur inconnu' });

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect' });

  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username });
});

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(req.user.username);
  if (!bcrypt.compareSync(currentPassword, user.password_hash))
    return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, req.user.username);
  res.json({ ok: true });
});

// ── Player routes ───────────────────────────────────────────────────────────
app.get('/api/players', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM players').all();
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

app.get('/api/players/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM players WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Joueur non trouvé' });
  res.json({
    p: row.pseudo, a: row.a, c: row.c,
    t: JSON.parse(row.tags), r: JSON.parse(row.reads),
    n: JSON.parse(row.notes), sz: JSON.parse(row.sz),
    src: row.src, updated_at: row.updated_at, updated_by: row.updated_by,
  });
});

app.put('/api/players/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const p = req.body;
  const existing = db.prepare('SELECT id FROM players WHERE id = ?').get(id);
  if (existing) {
    db.prepare(`
      UPDATE players SET pseudo=?, a=?, c=?, tags=?, reads=?, notes=?, sz=?, src=?,
      updated_at=CURRENT_TIMESTAMP, updated_by=?
      WHERE id=?
    `).run(p.p||'', p.a||0, p.c||0, JSON.stringify(p.t||[]),
           JSON.stringify(p.r||[]), JSON.stringify(p.n||[]),
           JSON.stringify(p.sz||{}), p.src||'KK', req.user.username, id);
  } else {
    db.prepare(`
      INSERT INTO players (id, pseudo, a, c, tags, reads, notes, sz, src, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, p.p||'', p.a||0, p.c||0, JSON.stringify(p.t||[]),
           JSON.stringify(p.r||[]), JSON.stringify(p.n||[]),
           JSON.stringify(p.sz||{}), p.src||'KK', req.user.username);
  }
  res.json({ ok: true });
});

app.post('/api/players/:id/note', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { text, conf } = req.body;
  if (!text) return res.status(400).json({ error: 'Note vide' });

  let row = db.prepare('SELECT * FROM players WHERE id = ?').get(id);
  if (!row) {
    db.prepare('INSERT INTO players (id, notes, updated_by) VALUES (?, ?, ?)').run(
      id, JSON.stringify([]), req.user.username
    );
    row = db.prepare('SELECT * FROM players WHERE id = ?').get(id);
  }

  const notes = JSON.parse(row.notes || '[]');
  notes.push({
    t: text, conf: conf || 1,
    ts: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
    by: req.user.username,
  });
  db.prepare('UPDATE players SET notes=?, updated_at=CURRENT_TIMESTAMP, updated_by=? WHERE id=?')
    .run(JSON.stringify(notes), req.user.username, id);
  res.json({ ok: true });
});

// ── Reviews ─────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id TEXT NOT NULL,
    note TEXT NOT NULL,
    conf INTEGER DEFAULT 1,
    ts TEXT,
    by TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.get('/api/reviews', authMiddleware, (req, res) => {
  const rows = db.prepare("SELECT * FROM reviews WHERE status='pending' ORDER BY created_at DESC").all();
  res.json(rows);
});

app.post('/api/reviews', authMiddleware, (req, res) => {
  const { player_id, note, conf } = req.body;
  db.prepare('INSERT INTO reviews (player_id, note, conf, ts, by) VALUES (?, ?, ?, ?, ?)')
    .run(player_id, note, conf || 1,
         new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
         req.user.username);
  res.json({ ok: true });
});

app.patch('/api/reviews/:id', authMiddleware, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE reviews SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true });
});

// ── AI Analysis route ───────────────────────────────────────────────────────
app.post('/api/analyze', authMiddleware, async (req, res) => {
  const { player_id, note } = req.body;
  const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_KEY) return res.json({ analysis: 'Clé API Anthropic non configurée.' });

  const player = db.prepare('SELECT * FROM players WHERE id = ?').get(player_id);
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
    res.json({ analysis: 'Erreur lors de l\'analyse.' });
  }
});

// ── Catch-all → index.html ───────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Poker HUD running on port ${PORT}`);
});
