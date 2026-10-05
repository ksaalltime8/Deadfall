'use strict';
require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Server } = require('socket.io');

const PORT = Number(process.env.PORT || 5500);
const MONGODB_URI = String(process.env.MONGODB_URI || '').trim();
const JWT_SECRET = String(process.env.JWT_SECRET || '').trim();
const CLIENT_ORIGIN = String(process.env.CLIENT_ORIGIN || '*').trim().replace(/\/$/, '');

if (!JWT_SECRET) console.warn('[DEADFALL] WARNING: JWT_SECRET is missing. Authentication will not work.');
if (!MONGODB_URI) console.warn('[DEADFALL] WARNING: MONGODB_URI is missing. Database features will not work.');

const app = express();
const server = http.createServer(app);
const allowedOrigins = CLIENT_ORIGIN === '*' ? true : CLIENT_ORIGIN.split(',').map(v => v.trim()).filter(Boolean);
const io = new Server(server, { cors: { origin: allowedOrigins, methods: ['GET', 'POST'] } });

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: allowedOrigins }));
app.use(express.json({ limit: '1mb' }));

const id = mongoose.Schema.Types.ObjectId;
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true, maxlength: 30 },
  role: { type: String, enum: ['player', 'admin'], default: 'player' },
  xp: { type: Number, default: 0, min: 0 },
  level: { type: Number, default: 1, min: 1, max: 999 },
  kills: { type: Number, default: 0, min: 0 },
  banned: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
}));
const City = mongoose.model('City', new mongoose.Schema({
  userId: { type: id, unique: true, required: true, index: true },
  cityName: { type: String, default: 'New Haven', maxlength: 40 },
  food: { type: Number, default: 500, min: 0 },
  wood: { type: Number, default: 350, min: 0 },
  metal: { type: Number, default: 250, min: 0 },
  fuel: { type: Number, default: 100, min: 0 },
  wall: { type: Number, default: 100, min: 0, max: 100 },
  threat: { type: Number, default: 12, min: 0, max: 100 },
  updatedAt: { type: Date, default: Date.now }
}));
const Building = mongoose.model('Building', new mongoose.Schema({ userId: id, name: String, level: { type: Number, default: 1, min: 1, max: 99 } }, { timestamps: true }));
const Army = mongoose.model('Army', new mongoose.Schema({ userId: id, type: String, count: { type: Number, default: 0, min: 0, max: 100000 } }, { timestamps: true }));
const Mission = mongoose.model('Mission', new mongoose.Schema({ userId: id, code: String, progress: { type: Number, default: 0 }, claimed: { type: Boolean, default: false } }, { timestamps: true }));
const AdminLog = mongoose.model('AdminLog', new mongoose.Schema({ adminId: id, action: String, targetId: String, details: mongoose.Schema.Types.Mixed, createdAt: { type: Date, default: Date.now } }));

const BUILDINGS = ['Town Hall', 'Farm', 'Lumber Yard', 'Barracks', 'Workshop', 'Watchtower', 'Hospital', 'Armory'];
const ARMIES = ['Riflemen', 'Guards', 'Scouts'];
const MISSION_DEFS = [
  { code: 'streets', title: 'Clear the Streets', description: 'Kill 10 infected.', target: 10, reward: { xp: 120, food: 120 } },
  { code: 'gatherer', title: 'Secure Supplies', description: 'Reach 900 food.', target: 900, reward: { xp: 90, wood: 100 } },
  { code: 'firstblood', title: 'First Blood', description: 'Kill 1 infected.', target: 1, reward: { xp: 60, metal: 50 } },
  { code: 'builder', title: 'Fortify New Haven', description: 'Upgrade a building.', target: 1, reward: { xp: 100, metal: 100 } }
];

const online = new Map();
const socketsByUser = new Map();
const world = { threat: 12, phase: 'NIGHT', weather: 'CLEAR', horde: 0, maintenance: false, event: null, updatedAt: new Date() };

const clampInt = (value, min = 0, max = 100000000) => {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, Math.floor(n))) : min;
};
const cleanText = (value, max) => String(value ?? '').trim().slice(0, max);
const sendUser = (userId, event, payload) => {
  io.to(`user:${userId}`).emit(event, payload);
};
const broadcastWorld = (type, payload = {}) => io.emit('world:event', { type, ...payload });
const sign = user => jwt.sign({ id: String(user._id), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
const safeUser = user => ({
  _id: String(user._id), email: user.email, name: user.name, role: user.role,
  xp: user.xp, level: user.level, kills: user.kills, banned: user.banned,
  createdAt: user.createdAt, lastSeen: user.lastSeen
});

async function logAdmin(adminId, action, targetId, details = {}) {
  try { await AdminLog.create({ adminId, action, targetId: String(targetId || ''), details }); }
  catch (e) { console.error('[DEADFALL] audit log:', e.message); }
}

async function ensurePlayer(user) {
  const city = await City.findOne({ userId: user._id });
  if (!city) await City.create({ userId: user._id });
  const buildings = await Building.find({ userId: user._id });
  if (!buildings.length) await Building.insertMany(BUILDINGS.map(name => ({ userId: user._id, name, level: 1 })));
  const army = await Army.find({ userId: user._id });
  if (!army.length) await Army.insertMany([
    { userId: user._id, type: 'Riflemen', count: 20 },
    { userId: user._id, type: 'Guards', count: 10 },
    { userId: user._id, type: 'Scouts', count: 5 }
  ]);
  const missions = await Mission.find({ userId: user._id });
  if (!missions.length) await Mission.insertMany(MISSION_DEFS.map(x => ({ userId: user._id, code: x.code })));
}

async function playerState(user) {
  await ensurePlayer(user);
  const [city, buildings, army, missions] = await Promise.all([
    City.findOne({ userId: user._id }).lean(),
    Building.find({ userId: user._id }).sort({ name: 1 }).lean(),
    Army.find({ userId: user._id }).sort({ type: 1 }).lean(),
    Mission.find({ userId: user._id }).sort({ code: 1 }).lean()
  ]);
  return { user: safeUser(user), city, buildings, army, missions, world: { ...world, online: online.size } };
}

async function auth(req, res, next) {
  try {
    if (!JWT_SECRET) return res.status(503).json({ error: 'Server authentication is not configured.' });
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required.' });
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user || user.banned) return res.status(403).json({ error: 'Account unavailable.' });
    user.lastSeen = new Date();
    await user.save();
    req.user = user;
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid or expired session.' }); }
}
function admin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
}
function dbRequired(req, res, next) {
  if (mongoose.connection.readyState !== 1) return res.status(503).json({ error: 'Database is not connected yet. Try again in a few seconds.' });
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true, game: 'DEADFALL', version: '2.0.0', uptime: process.uptime(), database: mongoose.connection.readyState === 1, online: online.size, world }));

app.post('/api/auth/register', dbRequired, async (req, res) => {
  try {
    const name = cleanText(req.body.name, 30);
    const email = cleanText(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2) return res.status(400).json({ error: 'Survivor name must be at least 2 characters.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (await User.findOne({ email })) return res.status(409).json({ error: 'Email already registered.' });
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 12) });
    await ensurePlayer(user);
    res.json({ token: sign(user), state: await playerState(user) });
  } catch (e) { console.error('[DEADFALL] register:', e); res.status(500).json({ error: 'Registration failed.' }); }
});

app.post('/api/auth/login', dbRequired, async (req, res) => {
  try {
    const email = cleanText(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid email or password.' });
    if (user.banned) return res.status(403).json({ error: 'This survivor account is banned.' });
    user.lastSeen = new Date();
    await user.save();
    res.json({ token: sign(user), state: await playerState(user) });
  } catch (e) { console.error('[DEADFALL] login:', e); res.status(500).json({ error: 'Login failed.' }); }
});

app.get('/api/state', auth, dbRequired, async (req, res) => res.json(await playerState(req.user)));

app.post('/api/action/build', auth, dbRequired, async (req, res) => {
  try {
    const name = cleanText(req.body.name, 40);
    const [building, city] = await Promise.all([Building.findOne({ userId: req.user._id, name }), City.findOne({ userId: req.user._id })]);
    if (!building || !city) return res.status(404).json({ error: 'Building not found.' });
    const cost = { wood: 50 * building.level, metal: 30 * building.level };
    if (city.wood < cost.wood || city.metal < cost.metal) return res.status(400).json({ error: `Need ${cost.wood} wood and ${cost.metal} metal.` });
    city.wood -= cost.wood; city.metal -= cost.metal; building.level += 1; city.threat = Math.max(0, city.threat - 1); city.updatedAt = new Date();
    req.user.xp += 50;
    await Promise.all([city.save(), building.save(), req.user.save()]);
    sendUser(req.user._id, 'world:update', { reason: 'build' });
    res.json({ ok: true, state: await playerState(req.user) });
  } catch (e) { console.error('[DEADFALL] build:', e); res.status(500).json({ error: 'Build action failed.' }); }
});

app.post('/api/action/combat', auth, dbRequired, async (req, res) => {
  try {
    const [city, army] = await Promise.all([City.findOne({ userId: req.user._id }), Army.find({ userId: req.user._id })]);
    if (!city) return res.status(404).json({ error: 'City not found.' });
    const strength = army.reduce((sum, unit) => sum + unit.count, 0);
    if (strength < 1) return res.status(400).json({ error: 'No troops available.' });
    const kills = Math.max(1, Math.min(25, Math.floor(strength * (0.15 + Math.random() * 0.2))));
    const loss = Math.min(strength, Math.floor(kills * (0.08 + Math.random() * 0.1)));
    let remaining = loss;
    for (const unit of army) {
      const take = Math.min(unit.count, remaining); unit.count -= take; remaining -= take; await unit.save(); if (remaining <= 0) break;
    }
    city.threat = Math.max(0, city.threat - 3); city.food = Math.max(0, city.food - 10); await city.save();
    req.user.kills += kills; req.user.xp += kills * 15; await req.user.save();
    res.json({ ok: true, kills, loss, state: await playerState(req.user) });
  } catch (e) { console.error('[DEADFALL] combat:', e); res.status(500).json({ error: 'Combat failed.' }); }
});

app.post('/api/action/mission', auth, dbRequired, async (req, res) => {
  try {
    const code = cleanText(req.body.code, 40); const def = MISSION_DEFS.find(x => x.code === code);
    const mission = await Mission.findOne({ userId: req.user._id, code });
    if (!mission || !def) return res.status(404).json({ error: 'Mission not found.' });
    if (mission.claimed) return res.status(400).json({ error: 'Mission already claimed.' });
    const city = await City.findOne({ userId: req.user._id });
    if (code === 'firstblood' || code === 'streets') mission.progress = req.user.kills;
    else if (code === 'gatherer') mission.progress = city.food;
    else if (code === 'builder') mission.progress = Math.max(0, (await Building.find({ userId: req.user._id })).reduce((sum, b) => sum + b.level - 1, 0));
    if (mission.progress < def.target) return res.status(400).json({ error: 'Mission not complete.', progress: mission.progress, target: def.target });
    mission.claimed = true; req.user.xp += def.reward.xp || 0;
    while (req.user.xp >= req.user.level * 500) req.user.level += 1;
    for (const resource of ['food', 'wood', 'metal']) if (def.reward[resource]) city[resource] += def.reward[resource];
    await Promise.all([mission.save(), req.user.save(), city.save()]);
    res.json({ ok: true, state: await playerState(req.user) });
  } catch (e) { console.error('[DEADFALL] mission:', e); res.status(500).json({ error: 'Mission action failed.' }); }
});

app.get('/api/rankings', auth, dbRequired, async (req, res) => res.json({ players: await User.find({ banned: false }).sort({ kills: -1, xp: -1 }).limit(100).select('name level kills xp role').lean() }));
app.get('/api/map', auth, dbRequired, async (req, res) => {
  const cities = await City.find().select('userId cityName wall threat').limit(500).lean();
  const users = await User.find({ _id: { $in: cities.map(x => x.userId) } }).select('name level').lean();
  const by = new Map(users.map(u => [String(u._id), u]));
  res.json({ points: cities.map((c, i) => ({ id: String(c.userId), name: c.cityName || 'New Haven', owner: by.get(String(c.userId))?.name || 'Unknown', level: by.get(String(c.userId))?.level || 1, wall: c.wall, threat: c.threat, x: 10 + (i * 37) % 80, y: 12 + (i * 61) % 76 })) });
});

// ---------- GAME MASTER / ADMIN ----------
app.get('/api/admin/players', auth, dbRequired, admin, async (req, res) => res.json({ players: await User.find().sort({ lastSeen: -1 }).select('-password').limit(2000).lean() }));
app.get('/api/admin/player/:playerId', auth, dbRequired, admin, async (req, res) => {
  const user = await User.findById(req.params.playerId).select('-password');
  if (!user) return res.status(404).json({ error: 'Player not found.' });
  res.json({ state: await playerState(user) });
});
app.get('/api/admin/logs', auth, dbRequired, admin, async (req, res) => res.json({ logs: await AdminLog.find().sort({ createdAt: -1 }).limit(500).lean() }));

app.post('/api/admin/give', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const field = cleanText(req.body.field, 20); const amount = clampInt(req.body.amount, -100000000, 100000000);
  const user = await User.findById(targetId); if (!user) return res.status(404).json({ error: 'Player not found.' });
  if (['xp', 'kills', 'level'].includes(field)) {
    const min = field === 'level' ? 1 : 0; user[field] = clampInt((user[field] || 0) + amount, min, 100000000); await user.save();
  } else if (['food', 'wood', 'metal', 'fuel', 'wall', 'threat'].includes(field)) {
    const city = await City.findOne({ userId: targetId }); if (!city) return res.status(404).json({ error: 'City not found.' });
    const max = ['wall', 'threat'].includes(field) ? 100 : 100000000; city[field] = clampInt((city[field] || 0) + amount, 0, max); await city.save();
  } else return res.status(400).json({ error: 'Unsupported field.' });
  await logAdmin(req.user._id, 'GIVE', targetId, { field, amount }); sendUser(targetId, 'world:update', { reason: 'admin' }); res.json({ ok: true });
});

app.post('/api/admin/set-player', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const user = await User.findById(targetId); if (!user) return res.status(404).json({ error: 'Player not found.' });
  if (req.body.name !== undefined) user.name = cleanText(req.body.name, 30) || user.name;
  if (req.body.role !== undefined && ['player', 'admin'].includes(String(req.body.role))) user.role = String(req.body.role);
  if (req.body.banned !== undefined) user.banned = Boolean(req.body.banned);
  for (const field of ['xp', 'kills', 'level']) if (req.body[field] !== undefined) user[field] = clampInt(req.body[field], field === 'level' ? 1 : 0, 100000000);
  await user.save(); await logAdmin(req.user._id, 'SET_PLAYER', targetId, { role: user.role, banned: user.banned, name: user.name, xp: user.xp, level: user.level, kills: user.kills });
  if (user.banned) sendUser(targetId, 'account:disabled'); else sendUser(targetId, 'world:update', { reason: 'admin' });
  res.json({ ok: true, player: safeUser(user) });
});

app.post('/api/admin/set-city', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const city = await City.findOne({ userId: targetId }); if (!city) return res.status(404).json({ error: 'City not found.' });
  for (const field of ['food', 'wood', 'metal', 'fuel']) if (req.body[field] !== undefined) city[field] = clampInt(req.body[field], 0, 100000000);
  for (const field of ['wall', 'threat']) if (req.body[field] !== undefined) city[field] = clampInt(req.body[field], 0, 100);
  if (req.body.cityName !== undefined) city.cityName = cleanText(req.body.cityName, 40) || 'New Haven';
  await city.save(); await logAdmin(req.user._id, 'SET_CITY', targetId, req.body); sendUser(targetId, 'world:update', { reason: 'admin' }); res.json({ ok: true });
});

app.post('/api/admin/set-building', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const name = cleanText(req.body.name, 40);
  if (!BUILDINGS.includes(name)) return res.status(400).json({ error: 'Invalid building.' });
  const building = await Building.findOne({ userId: targetId, name }); if (!building) return res.status(404).json({ error: 'Building not found.' });
  building.level = clampInt(req.body.level, 1, 99); await building.save(); await logAdmin(req.user._id, 'SET_BUILDING', targetId, { name, level: building.level }); sendUser(targetId, 'world:update', { reason: 'admin' }); res.json({ ok: true });
});

app.post('/api/admin/set-army', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const type = cleanText(req.body.type, 30); if (!ARMIES.includes(type)) return res.status(400).json({ error: 'Invalid army type.' });
  const army = await Army.findOne({ userId: targetId, type }); if (!army) return res.status(404).json({ error: 'Army unit not found.' });
  army.count = clampInt(req.body.count, 0, 100000); await army.save(); await logAdmin(req.user._id, 'SET_ARMY', targetId, { type, count: army.count }); sendUser(targetId, 'world:update', { reason: 'admin' }); res.json({ ok: true });
});

app.post('/api/admin/reset-player', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); const user = await User.findById(targetId); if (!user) return res.status(404).json({ error: 'Player not found.' });
  user.xp = 0; user.level = 1; user.kills = 0;
  await Promise.all([user.save(), City.deleteOne({ userId: targetId }), Building.deleteMany({ userId: targetId }), Army.deleteMany({ userId: targetId }), Mission.deleteMany({ userId: targetId })]);
  await ensurePlayer(user); await logAdmin(req.user._id, 'RESET_PLAYER', targetId, {}); sendUser(targetId, 'world:update', { reason: 'reset' }); res.json({ ok: true });
});

app.post('/api/admin/delete-player', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); if (targetId === String(req.user._id)) return res.status(400).json({ error: 'You cannot delete yourself.' });
  const user = await User.findById(targetId); if (!user) return res.status(404).json({ error: 'Player not found.' });
  sendUser(targetId, 'account:disabled');
  await Promise.all([User.deleteOne({ _id: targetId }), City.deleteOne({ userId: targetId }), Building.deleteMany({ userId: targetId }), Army.deleteMany({ userId: targetId }), Mission.deleteMany({ userId: targetId })]);
  await logAdmin(req.user._id, 'DELETE_PLAYER', targetId, {}); res.json({ ok: true });
});

app.post('/api/admin/kick', auth, dbRequired, admin, async (req, res) => {
  const targetId = cleanText(req.body.playerId, 50); if (targetId === String(req.user._id)) return res.status(400).json({ error: 'You cannot kick yourself.' });
  const sockets = socketsByUser.get(targetId); if (sockets) for (const socketId of sockets) io.sockets.sockets.get(socketId)?.disconnect(true);
  await logAdmin(req.user._id, 'KICK', targetId, {}); res.json({ ok: true });
});

app.post('/api/admin/horde', auth, dbRequired, admin, async (req, res) => {
  const amount = clampInt(req.body.amount, 1, 100000); world.horde += amount; world.threat = Math.min(100, world.threat + Math.ceil(amount / 25)); world.updatedAt = new Date();
  broadcastWorld('horde', { amount, total: world.horde, threat: world.threat }); await logAdmin(req.user._id, 'HORDE', 'WORLD', { amount }); res.json({ ok: true, world });
});
app.post('/api/admin/world', auth, dbRequired, admin, async (req, res) => {
  if (req.body.threat !== undefined) world.threat = clampInt(req.body.threat, 0, 100);
  if (['DAY', 'NIGHT', 'DUSK'].includes(String(req.body.phase || ''))) world.phase = String(req.body.phase);
  if (['CLEAR', 'FOG', 'RAIN', 'STORM'].includes(String(req.body.weather || ''))) world.weather = String(req.body.weather);
  world.updatedAt = new Date(); broadcastWorld('world_control', { world }); await logAdmin(req.user._id, 'WORLD_CONTROL', 'WORLD', req.body); res.json({ ok: true, world });
});
app.post('/api/admin/broadcast', auth, dbRequired, admin, async (req, res) => {
  const title = cleanText(req.body.title || 'EMERGENCY BROADCAST', 80); const text = cleanText(req.body.message || req.body.text, 500);
  if (!text) return res.status(400).json({ error: 'Message required.' });
  world.event = { title, text, at: new Date().toISOString() }; broadcastWorld('broadcast', { title, text, at: world.event.at }); await logAdmin(req.user._id, 'BROADCAST', 'WORLD', { title, text }); res.json({ ok: true });
});
app.post('/api/admin/maintenance', auth, dbRequired, admin, async (req, res) => {
  world.maintenance = Boolean(req.body.enabled); broadcastWorld('maintenance', { enabled: world.maintenance }); await logAdmin(req.user._id, 'MAINTENANCE', 'WORLD', { enabled: world.maintenance }); res.json({ ok: true, enabled: world.maintenance });
});
app.post('/api/admin/clear-event', auth, dbRequired, admin, async (req, res) => { world.event = null; broadcastWorld('world_control', { world }); await logAdmin(req.user._id, 'CLEAR_EVENT', 'WORLD', {}); res.json({ ok: true }); });

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

io.on('connection', socket => {
  socket.emit('world:state', { ...world, online: online.size });
  socket.on('join', async data => {
    try {
      if (!JWT_SECRET) return;
      const payload = jwt.verify(String(data?.token || ''), JWT_SECRET); const user = await User.findById(payload.id);
      if (!user || user.banned) return;
      socket.userId = String(user._id); socket.join(`user:${user._id}`); online.set(socket.id, socket.userId);
      if (!socketsByUser.has(socket.userId)) socketsByUser.set(socket.userId, new Set()); socketsByUser.get(socket.userId).add(socket.id);
      io.emit('world:presence', { online: online.size });
    } catch (_) {}
  });
  socket.on('disconnect', () => {
    const userId = online.get(socket.id); online.delete(socket.id);
    if (userId && socketsByUser.has(userId)) { socketsByUser.get(userId).delete(socket.id); if (!socketsByUser.get(userId).size) socketsByUser.delete(userId); }
    io.emit('world:presence', { online: online.size });
  });
});

let tickBusy = false;
setInterval(async () => {
  if (tickBusy || mongoose.connection.readyState !== 1) return;
  tickBusy = true;
  try {
    const cities = await City.find();
    for (const city of cities) {
      city.food = Math.min(100000, city.food + 10);
      city.wood = Math.min(100000, city.wood + 8);
      city.metal = Math.min(100000, city.metal + 5);
      city.fuel = Math.min(100000, city.fuel + 1);
      if (world.horde > 0) { city.threat = Math.min(100, city.threat + 1); if (Math.random() < 0.08) city.wall = Math.max(0, city.wall - 1); }
      city.updatedAt = new Date(); await city.save();
    }
    world.threat = Math.max(0, Math.min(100, world.threat + (Math.random() < 0.35 ? 1 : -1)));
    if (world.horde > 0) world.horde = Math.max(0, world.horde - Math.max(1, Math.ceil(world.horde * 0.02)));
    world.updatedAt = new Date(); io.emit('world:tick', { world: { ...world, online: online.size } });
  } catch (e) { console.error('[DEADFALL] tick:', e.message); }
  finally { tickBusy = false; }
}, 60000);

server.listen(PORT, '0.0.0.0', async () => {
  console.log(`[DEADFALL] Server listening on 0.0.0.0:${PORT}`);
  if (!MONGODB_URI || !JWT_SECRET) return;
  try {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('[DEADFALL] MongoDB connected');
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const email = process.env.ADMIN_EMAIL.trim().toLowerCase(); let adminUser = await User.findOne({ email });
      if (!adminUser) {
        adminUser = await User.create({ email, name: 'COMMAND', role: 'admin', password: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12) });
        console.log(`[DEADFALL] Initial admin created: ${email}`);
      } else if (adminUser.role !== 'admin') { adminUser.role = 'admin'; await adminUser.save(); console.log(`[DEADFALL] Promoted admin: ${email}`); }
    }
  } catch (e) { console.error('[DEADFALL] MongoDB connection failed:', e.message); }
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));
