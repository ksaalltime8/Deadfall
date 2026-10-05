const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
require('dotenv').config();

const PORT = Number(process.env.PORT) || 5500;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CLIENT_URL = process.env.CLIENT_URL || 'https://iik27.com';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('[DEADFALL] MONGODB_URI is missing.');
  process.exit(1);
}

const app = express();
const server = http.createServer(app);
const allowedOrigins = [CLIENT_URL, 'https://www.iik27.com', 'http://localhost:5500', 'http://127.0.0.1:5500'];
const io = new Server(server, {
  cors: { origin: allowedOrigins, methods: ['GET', 'POST'], credentials: false }
});

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Vary', 'Origin');
  }
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 60000, max: 240 }));

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true, maxlength: 30 },
  role: { type: String, enum: ['player', 'admin'], default: 'player', index: true },
  xp: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  kills: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: null }
});

const citySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, index: true },
  cityName: { type: String, default: 'New Haven', maxlength: 40 },
  food: { type: Number, default: 1200 },
  wood: { type: Number, default: 900 },
  metal: { type: Number, default: 700 },
  fuel: { type: Number, default: 500 },
  wall: { type: Number, default: 100 },
  threat: { type: Number, default: 12 },
  updatedAt: { type: Date, default: Date.now }
});

const buildingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  name: String,
  level: { type: Number, default: 1 }
}, { timestamps: true });
buildingSchema.index({ userId: 1, name: 1 }, { unique: true });

const armySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  type: String,
  count: { type: Number, default: 0 }
});
armySchema.index({ userId: 1, type: 1 }, { unique: true });

const missionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  code: String,
  progress: { type: Number, default: 0 },
  claimed: { type: Boolean, default: false }
});
missionSchema.index({ userId: 1, code: 1 }, { unique: true });

const adminLogSchema = new mongoose.Schema({
  adminId: mongoose.Schema.Types.ObjectId,
  action: String,
  details: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const City = mongoose.model('City', citySchema);
const Building = mongoose.model('Building', buildingSchema);
const Army = mongoose.model('Army', armySchema);
const Mission = mongoose.model('Mission', missionSchema);
const AdminLog = mongoose.model('AdminLog', adminLogSchema);

const buildingNames = ['Town Hall', 'Farm', 'Lumber Yard', 'Barracks', 'Workshop', 'Watchtower', 'Hospital', 'Armory'];
const armyDefaults = [['Riflemen', 20], ['Guards', 10], ['Scouts', 5]];
const missionCodes = ['streets', 'gatherer', 'firstblood', 'builder'];

async function seedUser(user) {
  await Promise.all([
    City.create({ userId: user._id }),
    ...buildingNames.map(name => Building.updateOne({ userId: user._id, name }, { $setOnInsert: { userId: user._id, name, level: 1 } }, { upsert: true })),
    ...armyDefaults.map(([type, count]) => Army.updateOne({ userId: user._id, type }, { $setOnInsert: { userId: user._id, type, count } }, { upsert: true })),
    ...missionCodes.map(code => Mission.updateOne({ userId: user._id, code }, { $setOnInsert: { userId: user._id, code, progress: 0, claimed: false } }, { upsert: true }))
  ]);
}

function publicUser(u) {
  return { id: u._id, email: u.email, name: u.name, role: u.role, xp: u.xp, level: u.level, kills: u.kills };
}

async function state(id) {
  const [u, c, buildings, army, missions] = await Promise.all([
    User.findById(id).select('email name role xp level kills').lean(),
    City.findOne({ userId: id }).lean(),
    Building.find({ userId: id }).select('name level -_id').lean(),
    Army.find({ userId: id }).select('type count -_id').lean(),
    Mission.find({ userId: id }).select('code progress claimed -_id').lean()
  ]);
  return { user: u, city: c, buildings, army, missions, online: io.sockets.adapter.rooms.get('world')?.size || 0 };
}

function token(u) { return jwt.sign({ id: String(u._id), role: u.role }, SECRET, { expiresIn: '7d' }); }

async function auth(req, res, next) {
  try {
    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const p = jwt.verify(raw, SECRET);
    const u = await User.findById(p.id).select('email name role xp level kills');
    if (!u) return res.sendStatus(401);
    req.user = u;
    next();
  } catch { res.sendStatus(401); }
}

function admin(req, res, next) {
  if (req.user?.role !== 'admin') return res.sendStatus(403);
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'mongodb' : 'disconnected' }));

app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email || '') || !password || password.length < 8 || !name) {
    return res.status(400).json({ error: 'Valid name, email and 8+ character password required' });
  }
  try {
    const user = await User.create({ email: String(email).toLowerCase(), password: await bcrypt.hash(password, 12), name: String(name).slice(0, 30) });
    await seedUser(user);
    res.json({ token: token(user), state: await state(user._id) });
  } catch (e) {
    if (e?.code === 11000) return res.status(409).json({ error: 'Email already registered' });
    console.error(e); res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const u = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
    if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) return res.status(401).json({ error: 'Invalid credentials' });
    u.lastSeen = new Date(); await u.save();
    res.json({ token: token(u), state: await state(u._id) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed' }); }
});

app.get('/api/state', auth, async (req, res) => res.json(await state(req.user._id)));

app.post('/api/action/build', auth, async (req, res) => {
  try {
    const { name } = req.body;
    const costs = { Farm: [120,80,30,0], 'Lumber Yard': [100,120,25,0], Barracks: [180,140,80,20], Workshop: [200,180,120,50], Watchtower: [160,120,100,30], Hospital: [220,160,150,50], Armory: [300,240,220,100] };
    if (!costs[name]) return res.status(400).json({ error: 'Unknown building' });
    const [c, b] = await Promise.all([City.findOne({ userId: req.user._id }), Building.findOne({ userId: req.user._id, name })]);
    if (!c || !b) return res.status(404).json({ error: 'City/building not found' });
    const [f,w,m,fu] = costs[name].map(v => v * b.level);
    if (c.food < f || c.wood < w || c.metal < m || c.fuel < fu) return res.status(400).json({ error: 'Not enough resources' });
    c.food -= f; c.wood -= w; c.metal -= m; c.fuel -= fu; c.updatedAt = new Date();
    b.level += 1;
    await Promise.all([c.save(), b.save(), User.updateOne({ _id: req.user._id }, { $inc: { xp: 50 } })]);
    res.json(await state(req.user._id));
    io.to('world').emit('world:update', { type: 'building', player: req.user.name });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Build action failed' }); }
});

app.post('/api/action/mission', auth, async (req, res) => {
  try {
    const code = req.body.code;
    const m = await Mission.findOne({ userId: req.user._id, code });
    if (!m || m.claimed) return res.status(400).json({ error: 'Mission unavailable' });
    const need = { streets: 10, gatherer: 100, firstblood: 1, builder: 3 }[code] || 1;
    const amount = Math.max(0, Math.min(1000, Number(req.body.amount) || 1));
    m.progress = Math.min(need, m.progress + amount);
    if (m.progress >= need) {
      m.claimed = true;
      await Promise.all([
        m.save(),
        User.updateOne({ _id: req.user._id }, { $inc: { xp: 100, kills: code === 'firstblood' ? 1 : 0 } }),
        City.updateOne({ userId: req.user._id }, { $inc: { food: 250, wood: 200, metal: 150, fuel: 100 } })
      ]);
    } else await m.save();
    res.json(await state(req.user._id));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Mission action failed' }); }
});

app.post('/api/action/combat', auth, async (req, res) => {
  try {
    const troops = await Army.aggregate([{ $match: { userId: req.user._id } }, { $group: { _id: null, n: { $sum: '$count' } } }]);
    const soldiers = troops[0]?.n || 0;
    if (soldiers < 5) return res.status(400).json({ error: 'Need at least 5 troops' });
    const enemy = Math.floor(Math.random() * 70) + 20;
    const power = soldiers + Math.floor(Math.random() * 40);
    const win = power >= enemy;
    const losses = win ? Math.max(1, Math.floor(enemy / 20)) : Math.max(2, Math.floor(soldiers / 4));
    await Army.updateOne({ userId: req.user._id, type: 'Riflemen' }, { $inc: { count: -losses } });
    await City.updateOne({ userId: req.user._id }, { $inc: { threat: win ? -5 : 8 } });
    if (win) await User.updateOne({ _id: req.user._id }, { $inc: { xp: 120, kills: Math.max(1, Math.floor(enemy / 15)) } });
    res.json({ win, enemy, power, state: await state(req.user._id) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Combat failed' }); }
});

app.get('/api/rankings', auth, async (req, res) => res.json(await User.find({ role: 'player' }).select('name level xp kills -_id').sort({ xp: -1 }).limit(50).lean()));
app.get('/api/map', auth, async (req, res) => {
  try {
    const cities = await User.aggregate([
      {
        $match: { role: 'player' }
      },
      {
        $lookup: {
          from: 'cities',
          localField: '_id',
          foreignField: 'userId',
          as: 'cityData'
        }
      },
      {
        $unwind: '$cityData'
      },
      {
        $project: {
          id: '$_id',
          name: 1,
          city: '$cityData.cityName',
          threat: '$cityData.threat',
          level: 1,
          kills: 1
        }
      },
      {
        $sort: { level: -1 }
      }
    ]);

    res.json(cities);
  } catch (error) {
    console.error('[DEADFALL] Map error:', error);
    res.status(500).json({
      error: 'Failed to load map data'
    });
  }
});
app.get('/api/admin/players', auth, admin, async (req, res) => res.json(await User.aggregate([{ $lookup: { from: 'cities', localField: '_id', foreignField: 'userId', as: 'city' } }, { $unwind: '$city' }, { $project: { id: '$_id', email: 1, name: 1, role: 1, xp: 1, level: 1, kills: 1, createdAt: 1, food: '$city.food', wood: '$city.wood', metal: '$city.metal', fuel: '$city.fuel', wall: '$city.wall', threat: '$city.threat' } }, { $sort: { createdAt: -1 } }]));

app.post('/api/admin/give', auth, admin, async (req, res) => {
  const { userId, resource, amount } = req.body;
  if (!['food','wood','metal','fuel'].includes(resource)) return res.sendStatus(400);
  const safeAmount = Math.max(-100000, Math.min(100000, Number(amount) || 0));
  await City.updateOne({ userId }, { $inc: { [resource]: safeAmount } });
  await AdminLog.create({ adminId: req.user._id, action: 'resource', details: `${resource}:${safeAmount} user:${userId}` });
  io.to('world').emit('world:update', { type: 'admin' });
  res.json({ ok: true });
});

app.post('/api/admin/horde', auth, admin, async (req, res) => {
  const amount = Math.max(1, Math.min(1000, Number(req.body.amount) || 50));
  await City.updateMany({}, { $inc: { threat: Math.floor(amount / 10) } });
  await AdminLog.create({ adminId: req.user._id, action: 'horde', details: `strength:${amount}` });
  io.to('world').emit('world:event', { title: 'GLOBAL HORDE', text: `A horde of ${amount} infected has entered the wasteland.` });
  res.json({ ok: true });
});

app.post('/api/admin/broadcast', auth, admin, async (req, res) => {
  const message = String(req.body.text || '').slice(0, 300);
  io.to('world').emit('world:event', { title: 'COMMAND BROADCAST', text: message });
  await AdminLog.create({ adminId: req.user._id, action: 'broadcast', details: message });
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, '../client')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../client/index.html')));

io.on('connection', socket => {
  socket.on('join', async tokenStr => {
    try {
      const p = jwt.verify(tokenStr, SECRET);
      const user = await User.findById(p.id);
      if (!user) return socket.disconnect();
      socket.data.userId = String(user._id);
      socket.join('world');
      user.lastSeen = new Date(); await user.save();
      const online = io.sockets.adapter.rooms.get('world')?.size || 1;
      socket.emit('world:presence', { online });
      socket.broadcast.to('world').emit('world:presence', { online });
    } catch { socket.disconnect(); }
  });
  socket.on('disconnect', () => {
    const online = io.sockets.adapter.rooms.get('world')?.size || 0;
    io.to('world').emit('world:presence', { online });
  });
});

setInterval(async () => {
  if (mongoose.connection.readyState !== 1) return;
  await City.updateMany({}, { $inc: { food: 5, wood: 4, metal: 3, fuel: 2 }, $set: { updatedAt: new Date() } });
  await City.updateMany({ food: { $gt: 100000 } }, { $set: { food: 100000 } });
  await City.updateMany({ wood: { $gt: 100000 } }, { $set: { wood: 100000 } });
  await City.updateMany({ metal: { $gt: 100000 } }, { $set: { metal: 100000 } });
  await City.updateMany({ fuel: { $gt: 100000 } }, { $set: { fuel: 100000 } });
  io.to('world').emit('world:tick', { ts: Date.now() });
}, 60000);

async function start() {
  await mongoose.connect(MONGODB_URI);
  console.log('[DEADFALL] MongoDB connected');
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@iik27.com').toLowerCase();
  let adminUser = await User.findOne({ email: adminEmail });
  if (!adminUser) {
    adminUser = await User.create({ email: adminEmail, password: await bcrypt.hash(process.env.ADMIN_PASSWORD || 'ChangeMe_123!', 12), name: 'Administrator', role: 'admin' });
    await seedUser(adminUser);
    console.log(`[DEADFALL] Admin account created: ${adminEmail}`);
  } else if (adminUser.role !== 'admin') {
    adminUser.role = 'admin'; await adminUser.save();
  }
  server.listen(PORT, '0.0.0.0', () => console.log(`DEADFALL backend running at ${process.env.PUBLIC_BACKEND_URL || 'https://game.k7devs.com'} on port ${PORT}`));
}

start().catch(err => { console.error('[DEADFALL] Startup failed:', err); process.exit(1); });
