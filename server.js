const express = require('express');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const E = process.env;
const CLIENT_ID = E.DISCORD_CLIENT_ID, CLIENT_SECRET = E.DISCORD_CLIENT_SECRET, REDIRECT = E.DISCORD_REDIRECT_URI;
const GUILD = E.DISCORD_GUILD_ID || '1554076915663380520';
const ROLE = E.DISCORD_ROLE_ID || '1554077319004557372';
const ADMIN_PW = E.ADMIN_PASSWORD || 'admin';
const DATA = path.join(__dirname, 'data.json');

let db = { dispatch: { active: false, key: '', startedAt: null }, threads: {} };
try { db = JSON.parse(fs.readFileSync(DATA)); } catch {}
const save = () => fs.writeFile(DATA, JSON.stringify(db), () => {});

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(session({ secret: E.SESSION_SECRET || 'dev', resave: false, saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 3, sameSite: 'lax' } }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Discord OAuth ----------
app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(12).toString('hex'); req.session.state = state;
  const p = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT, response_type: 'code',
    scope: 'identify guilds.members.read', state, prompt: 'none' });
  res.redirect('https://discord.com/oauth2/authorize?' + p);
});
app.get('/auth/callback', async (req, res) => {
  try {
    if (!req.query.code || req.query.state !== req.session.state) return res.redirect('/?err=auth');
    const tok = await (await fetch('https://discord.com/api/oauth2/token', { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code',
        code: req.query.code, redirect_uri: REDIRECT }) })).json();
    if (!tok.access_token) return res.redirect('/?err=token');
    const h = { Authorization: 'Bearer ' + tok.access_token };
    const u = await (await fetch('https://discord.com/api/users/@me', { headers: h })).json();
    const mr = await fetch(`https://discord.com/api/users/@me/guilds/${GUILD}/member`, { headers: h });
    const m = mr.ok ? await mr.json() : null;
    req.session.user = { id: 'd' + u.id, name: (m && m.nick) || u.global_name || u.username,
      avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=64` : null,
      inGuild: !!m, confirmed: !!(m && m.roles.includes(ROLE)) };
    res.redirect('/');
  } catch (e) { console.error(e); res.redirect('/?err=discord'); }
});
app.post('/auth/guest', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 32);
  if (!name) return res.status(400).json({ error: 'Pseudo requis' });
  req.session.user = { id: 'g' + crypto.randomBytes(6).toString('hex'), name: name + ' (invité)', avatar: null, inGuild: false, confirmed: false };
  res.json({ ok: true });
});
app.post('/auth/logout', (req, res) => { delete req.session.user; res.json({ ok: true }); });

// ---------- Joueurs ----------
const needUser = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'Non connecté' });
app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));
app.get('/api/state', needUser, (req, res) => {
  const u = req.session.user, t = db.threads[u.id];
  if (t && t.unreadUser) { t.unreadUser = 0; save(); }
  res.json({ user: u,
    dispatch: u.confirmed ? db.dispatch : { active: db.dispatch.active, key: null },
    messages: t ? t.messages : [] });
});
app.post('/api/message', needUser, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'Message vide' });
  const u = req.session.user;
  const t = db.threads[u.id] ||= { user: u, messages: [], unreadAdmin: 0, unreadUser: 0 };
  t.user = u; t.messages.push({ from: 'user', text, at: Date.now() }); t.unreadAdmin++; t.last = Date.now();
  save(); res.json({ ok: true });
});

// ---------- Admin ----------
const needAdmin = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Admin requis' });
app.post('/admin/login', (req, res) => {
  const a = Buffer.from(String(req.body.password || '')), b = Buffer.from(ADMIN_PW);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) { req.session.admin = true; return res.json({ ok: true }); }
  res.status(403).json({ error: 'Mot de passe incorrect' });
});
app.post('/admin/logout', (req, res) => { req.session.admin = false; res.json({ ok: true }); });
app.get('/api/admin/state', needAdmin, (req, res) => {
  const threads = Object.entries(db.threads).map(([id, t]) => ({ id, user: t.user, messages: t.messages,
    unread: t.unreadAdmin, last: t.last })).sort((a, b) => b.last - a.last);
  res.json({ dispatch: db.dispatch, threads });
});
app.post('/api/admin/dispatch/start', needAdmin, (req, res) => {
  const key = String(req.body.key || '').trim().slice(0, 64);
  if (!key) return res.status(400).json({ error: 'Clé requise' });
  db.dispatch = { active: true, key, startedAt: Date.now() }; save(); res.json({ ok: true });
});
app.post('/api/admin/dispatch/stop', needAdmin, (req, res) => {
  db.dispatch = { active: false, key: '', startedAt: null }; save(); res.json({ ok: true });
});
app.post('/api/admin/reply', needAdmin, (req, res) => {
  const t = db.threads[req.body.id], text = String(req.body.text || '').trim().slice(0, 1000);
  if (!t || !text) return res.status(400).json({ error: 'Invalide' });
  t.messages.push({ from: 'admin', text, at: Date.now() }); t.unreadUser++; t.last = Date.now(); save(); res.json({ ok: true });
});
app.post('/api/admin/read', needAdmin, (req, res) => {
  const t = db.threads[req.body.id]; if (t) { t.unreadAdmin = 0; save(); } res.json({ ok: true });
});
app.post('/api/admin/delete', needAdmin, (req, res) => { delete db.threads[req.body.id]; save(); res.json({ ok: true }); });

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.listen(E.PORT || 3000, () => console.log('LAN Fortnite en ligne sur le port', E.PORT || 3000));
