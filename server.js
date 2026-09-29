const express = require('express');
const cookieSession = require('cookie-session');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const E = process.env;
const CLIENT_ID = E.DISCORD_CLIENT_ID, CLIENT_SECRET = E.DISCORD_CLIENT_SECRET, REDIRECT = E.DISCORD_REDIRECT_URI;
const GUILD = E.DISCORD_GUILD_ID || '1554076915663380520';
const ROLE = E.DISCORD_ROLE_ID || '1554077319004557372';
const LEAD_ROLE = E.DISCORD_LEAD_ROLE_ID || '1554077271898456134';
const STAFF_ROLE = E.DISCORD_STAFF_ROLE_ID || '1554185110926925844';
const SECRET = E.SESSION_SECRET || 'dev';
const ROLE_REFRESH_MS = 15000; // re-vérifie les rôles Discord toutes les 15 s
const DATA = path.join(__dirname, 'data.json');

let db = { dispatch: { active: false, key: '', startedAt: null }, threads: {}, announcements: [] };
try { db = JSON.parse(fs.readFileSync(DATA)); } catch {}
db.announcements ||= [];
const save = () => fs.writeFile(DATA, JSON.stringify(db), () => {});

// Code d'accès sans Discord : dérivé du pseudo + secret (survit aux redémarrages du serveur)
const norm = s => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
const accessCode = name => crypto.createHmac('sha256', SECRET).update('access:' + norm(name)).digest('hex').slice(0, 8).toUpperCase();

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cookieSession({ name: 'lan', keys: [SECRET], maxAge: 1000 * 60 * 60 * 24 * 3, sameSite: 'lax' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Rôles Discord ----------
// Mode 1 (recommandé) : bot Discord → rôles mis à jour instantanément, sans limite de requêtes.
// Mode 2 (secours) : vérification via le compte du joueur, toutes les 30 s, en respectant les limites Discord.
let botGuild = null;
if (E.DISCORD_BOT_TOKEN) {
  const { Client, GatewayIntentBits } = require('discord.js');
  const bot = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
  bot.once('ready', async () => {
    try { botGuild = await bot.guilds.fetch(GUILD); await botGuild.members.fetch();
      console.log('[bot] connecté,', botGuild.members.cache.size, 'membres chargés'); }
    catch (e) { console.error('[bot] impossible de charger le serveur :', e.message); botGuild = null; }
  });
  bot.on('guildMemberUpdate', (o, n) => console.log('[bot] rôles mis à jour pour', n.user.username));
  bot.on('error', e => console.error('[bot]', e.message));
  bot.login(E.DISCORD_BOT_TOKEN).catch(e => console.error('[bot] connexion refusée :', e.message));
}
function applyRoles(u, roles, inGuild, nick) {
  u.inGuild = inGuild;
  u.confirmed = roles.includes(ROLE);
  u.lead = roles.includes(LEAD_ROLE);
  u.staff = u.lead || roles.includes(STAFF_ROLE);
  if (nick) u.name = nick;
}
function rolesFromBot(u) {
  if (!botGuild) return false;
  const m = botGuild.members.cache.get(u.id.slice(1));
  applyRoles(u, m ? [...m.roles.cache.keys()] : [], !!m, m && m.nickname);
  return true;
}
async function fetchMember(token) {
  const r = await fetch(`https://discord.com/api/users/@me/guilds/${GUILD}/member`, { headers: { Authorization: 'Bearer ' + token } });
  if (r.status === 404 || r.status === 403) return { m: null, status: r.status };
  if (r.status === 429) { let ra = 30; try { ra = (await r.json()).retry_after || ra; } catch {} return { skip: true, status: 429, retryAfter: ra }; }
  if (!r.ok) return { skip: true, status: r.status };
  return { m: await r.json(), status: 200 };
}
async function refreshUser(req, res, next) {
  const u = req.session.user;
  if (u) {
    const before = JSON.stringify([u.confirmed, u.lead, u.staff, u.inGuild, u.name, u.rolesKnown]);
    if (u.id[0] === 'd') {
      if (rolesFromBot(u)) u.rolesKnown = true;
      else if (req.session.tok && Date.now() >= (u.nextCheck || 0)) {
        u.nextCheck = Date.now() + 30000;
        try {
          const r = await fetchMember(req.session.tok);
          if (!r.skip) { applyRoles(u, r.m ? r.m.roles : [], !!r.m, r.m && r.m.nick); u.rolesKnown = true; }
          else { if (r.retryAfter) u.nextCheck = Date.now() + Math.max(5, r.retryAfter) * 1000; console.log('[roles]', u.name, 'Discord', r.status, '→ nouvel essai plus tard'); }
        } catch (e) { console.error('[roles]', e.message); }
      }
    }
    if (u.id[0] === 'g') { // invité : accès donné par un admin (duo accepté)
      const t = db.threads[u.id];
      u.confirmed = !!(u.code || (t && t.duo && t.duo.status === 'accepted'));
    }
    if (JSON.stringify([u.confirmed, u.lead, u.staff, u.inGuild, u.name, u.rolesKnown]) !== before || u.id[0] === 'd') req.session.user = { ...u };
  }
  next();
}

// ---------- Connexion ----------
app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(12).toString('hex'); req.session.state = state;
  req.session.returnTo = req.query.admin ? '/admin' : '/';
  const p = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT, response_type: 'code',
    scope: 'identify guilds.members.read', state, prompt: 'none' });
  res.redirect('https://discord.com/oauth2/authorize?' + p);
});
app.get('/auth/callback', async (req, res) => {
  const back = req.session.returnTo || '/';
  try {
    if (!req.query.code || req.query.state !== req.session.state) return res.redirect(back + '?err=auth');
    const tok = await (await fetch('https://discord.com/api/oauth2/token', { method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'authorization_code',
        code: req.query.code, redirect_uri: REDIRECT }) })).json();
    if (!tok.access_token) return res.redirect(back + '?err=token');
    const u = await (await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tok.access_token } })).json();
    const user = { id: 'd' + u.id, name: u.global_name || u.username,
      avatar: u.avatar ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png?size=64` : null,
      confirmed: false, lead: false, staff: false, inGuild: false, rolesKnown: false, nextCheck: Date.now() + 30000 };
    if (rolesFromBot(user)) user.rolesKnown = true;
    else {
      const r = await fetchMember(tok.access_token);
      if (!r.skip) { applyRoles(user, r.m ? r.m.roles : [], !!r.m, r.m && r.m.nick); user.rolesKnown = true; }
      else { user.nextCheck = Date.now() + Math.max(5, r.retryAfter || 10) * 1000; console.log('[roles] connexion', user.name, 'Discord', r.status); }
    }
    console.log('[login]', user.name, JSON.stringify({ known: user.rolesKnown, confirmed: user.confirmed, lead: user.lead, staff: user.staff, inGuild: user.inGuild }));
    req.session.user = user; req.session.tok = tok.access_token; req.session.state = null;
    res.redirect(back);
  } catch (e) { console.error(e); res.redirect(back + '?err=discord'); }
});
app.post('/auth/guest', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 32);
  if (!name) return res.status(400).json({ error: 'name' });
  req.session.user = { id: 'g' + crypto.randomBytes(6).toString('hex'), name, guest: true, avatar: null, inGuild: false, confirmed: false };
  res.json({ ok: true });
});
// Connexion avec un code d'accès (joueurs sans Discord validés par un admin)
app.post('/auth/code', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 32), code = String(req.body.code || '').trim().toUpperCase();
  if (!name || code !== accessCode(name)) return res.status(403).json({ error: 'badcode' });
  const id = 'g' + crypto.createHash('sha256').update(norm(name)).digest('hex').slice(0, 12);
  req.session.user = { id, name, guest: true, code: true, avatar: null, inGuild: false, confirmed: true };
  res.json({ ok: true });
});
app.post('/auth/logout', (req, res) => { req.session = null; res.json({ ok: true }); });

// ---------- Joueurs ----------
const needUser = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'auth' });
app.get('/api/state', needUser, refreshUser, (req, res) => {
  const u = req.session.user, t = db.threads[u.id];
  if (t && t.unreadUser) { t.unreadUser = 0; save(); }
  const duo = t && t.duo ? { ...t.duo } : null;
  if (duo && duo.status === 'accepted') { duo.myCode = accessCode(u.name); duo.mateCode = accessCode(duo.mate); }
  res.json({ user: u,
    dispatch: u.confirmed ? db.dispatch : { active: db.dispatch.active, key: null },
    invited: !!(t && t.invited), duo,
    announcements: db.announcements.filter(a => a.audience === 'all' || u.confirmed).slice(-10).reverse(),
    messages: t ? t.messages : [] });
});
const thread = u => {
  const t = db.threads[u.id] ||= { user: u, messages: [], unreadAdmin: 0, unreadUser: 0, last: Date.now() };
  t.user = { id: u.id, name: u.name, guest: !!u.guest, confirmed: !!u.confirmed, avatar: u.avatar }; return t;
};
app.post('/api/message', needUser, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'empty' });
  const t = thread(req.session.user);
  t.messages.push({ from: 'user', text, at: Date.now() }); t.unreadAdmin++; t.last = Date.now();
  save(); res.json({ ok: true });
});
// L'invité renseigne le pseudo de son mate → demande de duo côté admin
app.post('/api/duo', needUser, (req, res) => {
  const t = db.threads[req.session.user.id], mate = String(req.body.mate || '').trim().slice(0, 32);
  if (!t || !t.invited || !mate) return res.status(400).json({ error: 'invalid' });
  if (t.duo && t.duo.status === 'accepted') return res.status(400).json({ error: 'done' });
  t.duo = { mate, status: 'pending', at: Date.now() }; t.last = Date.now(); save(); res.json({ ok: true });
});

// ---------- Staff / Admin ----------
const needAdmin = (req, res, next) => req.session.user && req.session.user.staff ? next() : res.status(401).json({ error: 'staff', user: req.session.user || null });
const needLead = (req, res, next) => req.session.user && req.session.user.lead ? next() : res.status(403).json({ error: 'lead' });
const staffGate = [(req, res, next) => req.session.user ? next() : res.status(401).json({ error: 'staff', user: null }), refreshUser, needAdmin];

app.get('/api/admin/state', staffGate, (req, res) => {
  const u = req.session.user;
  const threads = Object.entries(db.threads).map(([id, t]) => ({ id, user: t.user, messages: t.messages,
    unread: t.unreadAdmin, last: t.last, invited: !!t.invited,
    duo: t.duo ? { ...t.duo, codes: t.duo.status === 'accepted' ? [accessCode(t.user.name), accessCode(t.duo.mate)] : null } : null })).sort((a, b) => b.last - a.last);
  res.json({ me: u, dispatch: u.lead ? db.dispatch : null, threads, announcements: db.announcements.slice(-20).reverse() });
});
app.post('/api/admin/dispatch/start', staffGate, needLead, (req, res) => {
  const key = String(req.body.key || '').trim().slice(0, 64);
  if (!key) return res.status(400).json({ error: 'key' });
  db.dispatch = { active: true, key, startedAt: Date.now() }; save(); res.json({ ok: true });
});
app.post('/api/admin/dispatch/stop', staffGate, needLead, (req, res) => {
  db.dispatch = { active: false, key: '', startedAt: null }; save(); res.json({ ok: true });
});
app.post('/api/admin/reply', staffGate, (req, res) => {
  const t = db.threads[req.body.id], text = String(req.body.text || '').trim().slice(0, 1000);
  if (!t || !text) return res.status(400).json({ error: 'invalid' });
  t.messages.push({ from: 'admin', by: req.session.user.name, text, at: Date.now() }); t.unreadUser++; t.last = Date.now(); save(); res.json({ ok: true });
});
app.post('/api/admin/read', staffGate, (req, res) => {
  const t = db.threads[req.body.id]; if (t) { t.unreadAdmin = 0; save(); } res.json({ ok: true });
});
app.post('/api/admin/delete', staffGate, needLead, (req, res) => { delete db.threads[req.body.id]; save(); res.json({ ok: true }); });
// Donner l'accès à un joueur sans Discord (étape 1 : il peut déclarer son mate)
app.post('/api/admin/invite', staffGate, needLead, (req, res) => {
  const t = db.threads[req.body.id]; if (!t || !t.user.guest) return res.status(400).json({ error: 'invalid' });
  t.invited = true; t.unreadUser++; t.last = Date.now(); save(); res.json({ ok: true });
});
// Étape 2 : accepter / refuser le duo complet
app.post('/api/admin/duo', staffGate, needLead, (req, res) => {
  const t = db.threads[req.body.id]; if (!t || !t.duo) return res.status(400).json({ error: 'invalid' });
  t.duo.status = req.body.accept ? 'accepted' : 'refused'; t.duo.by = req.session.user.name;
  t.unreadUser++; t.last = Date.now(); save();
  res.json({ ok: true, codes: req.body.accept ? { [t.user.name]: accessCode(t.user.name), [t.duo.mate]: accessCode(t.duo.mate) } : null });
});

// Annonces à tous les joueurs
app.post('/api/admin/announce', staffGate, needLead, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'empty' });
  db.announcements.push({ id: crypto.randomBytes(5).toString('hex'), text, by: req.session.user.name,
    audience: req.body.audience === 'confirmed' ? 'confirmed' : 'all', important: !!req.body.important, at: Date.now() });
  db.announcements = db.announcements.slice(-50); save(); res.json({ ok: true });
});
app.post('/api/admin/announce/delete', staffGate, needLead, (req, res) => {
  db.announcements = db.announcements.filter(a => a.id !== req.body.id); save(); res.json({ ok: true });
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.listen(E.PORT || 3000, () => console.log('LAN Fortnite en ligne sur le port', E.PORT || 3000));
