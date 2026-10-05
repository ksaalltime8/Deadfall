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

// ============================================================
// DEADFALL CONFIGURATION
// ============================================================

const PORT = Number(process.env.PORT || 5500);

const MONGODB_URI = String(
  process.env.MONGODB_URI || ''
).trim();

const JWT_SECRET = String(
  process.env.JWT_SECRET || ''
).trim();

const CLIENT_ORIGIN = String(
  process.env.CLIENT_ORIGIN || ''
).trim();

if (!JWT_SECRET) {
  console.warn(
    '[DEADFALL] WARNING: JWT_SECRET is missing. Authentication will not work.'
  );
}

if (!MONGODB_URI) {
  console.warn(
    '[DEADFALL] WARNING: MONGODB_URI is missing. Database features will not work.'
  );
}

// ============================================================
// EXPRESS / HTTP
// ============================================================

const app = express();
const server = http.createServer(app);

// ============================================================
// CORS
// ============================================================
//
// Production frontend:
//   https://iik27.com
//   https://www.iik27.com
//
// Development:
//   http://localhost:5500
//   http://127.0.0.1:5500
//
// CLIENT_ORIGIN from .env is also accepted.
// ============================================================

const defaultOrigins = [
  'https://iik27.com',
  'https://www.iik27.com',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

const envOrigins = CLIENT_ORIGIN
  ? CLIENT_ORIGIN
      .split(',')
      .map(v => v.trim().replace(/\/$/, ''))
      .filter(Boolean)
  : [];

const allowedOrigins = [
  ...new Set([...defaultOrigins, ...envOrigins])
];

const isAllowedOrigin = origin => {
  if (!origin) return true;

  const normalized = String(origin)
    .trim()
    .replace(/\/$/, '');

  return allowedOrigins.includes(normalized);
};

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }

    console.warn(
      `[DEADFALL CORS] Blocked origin: ${origin}`
    );

    // Returning false instead of throwing prevents the
    // backend from generating an unnecessary 500 response.
    return callback(null, false);
  },

  methods: [
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
    'OPTIONS'
  ],

  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept'
  ],

  credentials: true,

  optionsSuccessStatus: 204
};

// ============================================================
// SOCKET.IO
// ============================================================

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },

  transports: [
    'polling',
    'websocket'
  ],

  pingTimeout: 20000,
  pingInterval: 25000,

  connectTimeout: 10000
});

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(cors(corsOptions));

app.use(
  express.json({
    limit: '1mb'
  })
);

// ============================================================
// DATABASE MODELS
// ============================================================

const id = mongoose.Schema.Types.ObjectId;

// ------------------------------------------------------------
// USER
// ------------------------------------------------------------

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 30
    },

    role: {
      type: String,
      enum: ['player', 'admin'],
      default: 'player'
    },

    xp: {
      type: Number,
      default: 0,
      min: 0
    },

    level: {
      type: Number,
      default: 1,
      min: 1,
      max: 999
    },

    kills: {
      type: Number,
      default: 0,
      min: 0
    },

    banned: {
      type: Boolean,
      default: false
    },

    createdAt: {
      type: Date,
      default: Date.now
    },

    lastSeen: {
      type: Date,
      default: Date.now
    }
  })
);

// ------------------------------------------------------------
// CITY
// ------------------------------------------------------------

const City = mongoose.model(
  'City',
  new mongoose.Schema({
    userId: {
      type: id,
      unique: true,
      required: true,
      index: true
    },

    cityName: {
      type: String,
      default: 'New Haven',
      maxlength: 40
    },

    food: {
      type: Number,
      default: 500,
      min: 0
    },

    wood: {
      type: Number,
      default: 350,
      min: 0
    },

    metal: {
      type: Number,
      default: 250,
      min: 0
    },

    fuel: {
      type: Number,
      default: 100,
      min: 0
    },

    wall: {
      type: Number,
      default: 100,
      min: 0,
      max: 100
    },

    threat: {
      type: Number,
      default: 12,
      min: 0,
      max: 100
    },

    updatedAt: {
      type: Date,
      default: Date.now
    }
  })
);

// ------------------------------------------------------------
// BUILDINGS
// ------------------------------------------------------------

const Building = mongoose.model(
  'Building',
  new mongoose.Schema(
    {
      userId: {
        type: id,
        required: true,
        index: true
      },

      name: {
        type: String,
        required: true
      },

      level: {
        type: Number,
        default: 1,
        min: 1,
        max: 99
      }
    },
    {
      timestamps: true
    }
  )
);

// ------------------------------------------------------------
// ARMY
// ------------------------------------------------------------

const Army = mongoose.model(
  'Army',
  new mongoose.Schema(
    {
      userId: {
        type: id,
        required: true,
        index: true
      },

      type: {
        type: String,
        required: true
      },

      count: {
        type: Number,
        default: 0,
        min: 0,
        max: 100000
      }
    },
    {
      timestamps: true
    }
  )
);

// ------------------------------------------------------------
// MISSIONS
// ------------------------------------------------------------

const Mission = mongoose.model(
  'Mission',
  new mongoose.Schema(
    {
      userId: {
        type: id,
        required: true,
        index: true
      },

      code: {
        type: String,
        required: true
      },

      progress: {
        type: Number,
        default: 0,
        min: 0
      },

      claimed: {
        type: Boolean,
        default: false
      }
    },
    {
      timestamps: true
    }
  )
);

// ------------------------------------------------------------
// ADMIN LOG
// ------------------------------------------------------------

const AdminLog = mongoose.model(
  'AdminLog',
  new mongoose.Schema({
    adminId: {
      type: id,
      required: true
    },

    action: {
      type: String,
      required: true
    },

    targetId: {
      type: String,
      default: ''
    },

    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  })
);

// ============================================================
// GAME DATA
// ============================================================

const BUILDINGS = [
  'Town Hall',
  'Farm',
  'Lumber Yard',
  'Barracks',
  'Workshop',
  'Watchtower',
  'Hospital',
  'Armory'
];

const ARMIES = [
  'Riflemen',
  'Guards',
  'Scouts'
];

const MISSION_DEFS = [
  {
    code: 'streets',
    title: 'Clear the Streets',
    description: 'Kill 10 infected.',
    target: 10,
    reward: {
      xp: 120,
      food: 120
    }
  },

  {
    code: 'gatherer',
    title: 'Secure Supplies',
    description: 'Reach 900 food.',
    target: 900,
    reward: {
      xp: 90,
      wood: 100
    }
  },

  {
    code: 'firstblood',
    title: 'First Blood',
    description: 'Kill 1 infected.',
    target: 1,
    reward: {
      xp: 60,
      metal: 50
    }
  },

  {
    code: 'builder',
    title: 'Fortify New Haven',
    description: 'Upgrade a building.',
    target: 1,
    reward: {
      xp: 100,
      metal: 100
    }
  }
];

// ============================================================
// ONLINE / WORLD STATE
// ============================================================

const online = new Map();
const socketsByUser = new Map();

const world = {
  threat: 12,
  phase: 'NIGHT',
  weather: 'CLEAR',
  horde: 0,
  maintenance: false,
  event: null,
  updatedAt: new Date()
};

// ============================================================
// HELPERS
// ============================================================

const clampInt = (
  value,
  min = 0,
  max = 100000000
) => {
  const n = Number(value);

  if (!Number.isFinite(n)) {
    return min;
  }

  return Math.max(
    min,
    Math.min(max, Math.floor(n))
  );
};

const cleanText = (
  value,
  max
) => {
  return String(value ?? '')
    .trim()
    .slice(0, max);
};

const sendUser = (
  userId,
  event,
  payload
) => {
  io
    .to(`user:${String(userId)}`)
    .emit(event, payload);
};

const broadcastWorld = (
  type,
  payload = {}
) => {
  io.emit(
    'world:event',
    {
      type,
      ...payload
    }
  );
};

const normalizeRole = role => {
  const value = String(role || '').trim().toLowerCase();

  return value === 'admin' ? 'admin' : 'player';
};

const sign = user => {
  return jwt.sign(
    {
      id: String(user._id),
      email: user.email,
      role: normalizeRole(user.role)
    },
    JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );
};

const safeUser = user => ({
  _id: String(user._id),
  id: String(user._id),
  email: user.email,
  name: user.name,
  role: normalizeRole(user.role),
  xp: Number(user.xp || 0),
  level: Number(user.level || 1),
  kills: Number(user.kills || 0),
  banned: Boolean(user.banned),
  createdAt: user.createdAt,
  lastSeen: user.lastSeen
});

const worldState = () => ({
  ...world,
  online: online.size
});

// ============================================================
// XP / LEVEL
// ============================================================

function processLevel(user) {
  user.level = clampInt(
    user.level || 1,
    1,
    999
  );

  user.xp = clampInt(
    user.xp || 0,
    0,
    100000000
  );

  while (
    user.level < 999 &&
    user.xp >= user.level * 500
  ) {
    user.level += 1;
  }
}

// ============================================================
// MISSION PROGRESS
// ============================================================
//
// This is important.
//
// Previously the database's stored mission.progress could stay
// at 0 even though the player had already completed the mission.
// The frontend therefore didn't know the mission was complete.
//
// We calculate the live progress whenever playerState() runs.
// ============================================================

async function calculateMissionProgress(
  user,
  city
) {
  const buildings = await Building.find({
    userId: user._id
  })
    .select('level')
    .lean();

  const upgradedBuildings = buildings.reduce(
    (sum, building) =>
      sum + Math.max(0, Number(building.level || 1) - 1),
    0
  );

  return {
    streets: clampInt(
      user.kills || 0,
      0,
      100000000
    ),

    firstblood: clampInt(
      user.kills || 0,
      0,
      100000000
    ),

    gatherer: clampInt(
      city?.food || 0,
      0,
      100000000
    ),

    builder: clampInt(
      upgradedBuildings,
      0,
      100000000
    )
  };
}

// ============================================================
// ADMIN LOGGING
// ============================================================

async function logAdmin(
  adminId,
  action,
  targetId,
  details = {}
) {
  try {
    await AdminLog.create({
      adminId,
      action,
      targetId: String(targetId || ''),
      details
    });
  } catch (e) {
    console.error(
      '[DEADFALL] audit log:',
      e.message
    );
  }
}



// ============================================================
// PLAYER INITIALIZATION
// ============================================================

async function ensurePlayer(user) {
  let city = await City.findOne({
    userId: user._id
  });

  if (!city) {
    city = await City.create({
      userId: user._id,
      cityName: 'New Haven'
    });
  }

  const buildings = await Building.find({
    userId: user._id
  });

  if (!buildings.length) {
    await Building.insertMany(
      BUILDINGS.map(name => ({
        userId: user._id,
        name,
        level: 1
      }))
    );
  } else {
    // Repair missing default buildings for older accounts.
    const existingNames = new Set(
      buildings.map(b => b.name)
    );

    const missingBuildings = BUILDINGS
      .filter(name => !existingNames.has(name))
      .map(name => ({
        userId: user._id,
        name,
        level: 1
      }));

    if (missingBuildings.length) {
      await Building.insertMany(
        missingBuildings
      );
    }
  }

  const army = await Army.find({
    userId: user._id
  });

  if (!army.length) {
    await Army.insertMany([
      {
        userId: user._id,
        type: 'Riflemen',
        count: 20
      },

      {
        userId: user._id,
        type: 'Guards',
        count: 10
      },

      {
        userId: user._id,
        type: 'Scouts',
        count: 5
      }
    ]);
  } else {
    const existingArmy = new Set(
      army.map(a => a.type)
    );

    const defaults = [
      ['Riflemen', 20],
      ['Guards', 10],
      ['Scouts', 5]
    ];

    const missingArmy = defaults
      .filter(([type]) => !existingArmy.has(type))
      .map(([type, count]) => ({
        userId: user._id,
        type,
        count
      }));

    if (missingArmy.length) {
      await Army.insertMany(
        missingArmy
      );
    }
  }

  const missions = await Mission.find({
    userId: user._id
  });

  if (!missions.length) {
    await Mission.insertMany(
      MISSION_DEFS.map(def => ({
        userId: user._id,
        code: def.code,
        progress: 0,
        claimed: false
      }))
    );
  } else {
    const existingCodes = new Set(
      missions.map(m => m.code)
    );

    const missingMissions = MISSION_DEFS
      .filter(def => !existingCodes.has(def.code))
      .map(def => ({
        userId: user._id,
        code: def.code,
        progress: 0,
        claimed: false
      }));

    if (missingMissions.length) {
      await Mission.insertMany(
        missingMissions
      );
    }
  }
}

// ============================================================
// PLAYER STATE
// ============================================================

async function playerState(user) {
  await ensurePlayer(user);

  const [
    city,
    buildings,
    army,
    missions
  ] = await Promise.all([
    City.findOne({
      userId: user._id
    }).lean(),

    Building.find({
      userId: user._id
    })
      .sort({ name: 1 })
      .lean(),

    Army.find({
      userId: user._id
    })
      .sort({ type: 1 })
      .lean(),

    Mission.find({
      userId: user._id
    })
      .sort({ code: 1 })
      .lean()
  ]);

  // Calculate mission progress LIVE.
  const progress = await calculateMissionProgress(
    user,
    city
  );

  const syncedMissions = missions.map(
    mission => ({
      ...mission,
      progress: Math.max(
        Number(mission.progress || 0),
        Number(progress[mission.code] || 0)
      )
    })
  );

  return {
    user: safeUser(user),

    city,

    buildings,

    army,

    missions: syncedMissions,

    world: worldState()
  };
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

async function auth(
  req,
  res,
  next
) {
  try {
    if (!JWT_SECRET) {
      return res.status(503).json({
        error:
          'Server authentication is not configured.'
      });
    }

    const header =
      req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        error:
          'Authentication required.'
      });
    }

    const token = header.slice(7);

    const payload = jwt.verify(
      token,
      JWT_SECRET
    );

    const user = await User.findById(
      payload.id
    );

    if (!user || user.banned) {
      return res.status(403).json({
        error:
          'Account unavailable.'
      });
    }

    user.lastSeen = new Date();

    await user.save();

    req.user = user;

    next();

  } catch (e) {
    return res.status(401).json({
      error:
        'Invalid or expired session.'
    });
  }
}

// ============================================================
// ADMIN MIDDLEWARE
// ============================================================

function admin(
  req,
  res,
  next
) {
  if (
    req.user?.role !== 'admin'
  ) {
    return res.status(403).json({
      error:
        'Admin access required.'
    });
  }

  next();
}


// ============================================================
// DATABASE REQUIRED
// ============================================================

function dbRequired(
  req,
  res,
  next
) {
  if (
    mongoose.connection.readyState !== 1
  ) {
    return res.status(503).json({
      error:
        'Database is not connected yet. Try again in a few seconds.'
    });
  }

  next();
}

// ============================================================
// HEALTH
// ============================================================

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,
      game: 'DEADFALL',
      version: '2.1.0',
      uptime: process.uptime(),
      database:
        mongoose.connection.readyState === 1,
      online: online.size,
      world: worldState()
    });
  }
);

// ============================================================
// AUTH — REGISTER
// ============================================================

app.post(
  '/api/auth/register',
  dbRequired,
  async (req, res) => {
    try {
      const name = cleanText(
        req.body.name,
        30
      );

      const email = cleanText(
        req.body.email,
        120
      ).toLowerCase();

      const password = String(
        req.body.password || ''
      );

      if (name.length < 2) {
        return res.status(400).json({
          error:
            'Survivor name must be at least 2 characters.'
        });
      }

      if (
        !/^\S+@\S+\.\S+$/.test(email)
      ) {
        return res.status(400).json({
          error:
            'Enter a valid email address.'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'Password must be at least 6 characters.'
        });
      }

      const existing =
        await User.findOne({ email });

      if (existing) {
        return res.status(409).json({
          error:
            'Email already registered.'
        });
      }

      const user =
        await User.create({
          name,
          email,
          password:
            await bcrypt.hash(
              password,
              12
            )
        });

      await ensurePlayer(user);

      res.json({
        token: sign(user),
        state:
          await playerState(user)
      });

    } catch (e) {
      console.error(
        '[DEADFALL] register:',
        e
      );

      res.status(500).json({
        error:
          'Registration failed.'
      });
    }
  }
);

// ============================================================
// AUTH — LOGIN
// ============================================================

app.post(
  '/api/auth/login',
  dbRequired,
  async (req, res) => {
    try {
      const email = cleanText(
        req.body.email,
        120
      ).toLowerCase();

      const password = String(
        req.body.password || ''
      );

      const user =
        await User.findOne({ email });

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password
        ))
      ) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      if (user.banned) {
        return res.status(403).json({
          error:
            'This survivor account is banned.'
        });
      }

      user.lastSeen = new Date();

      await user.save();

      res.json({
        token: sign(user),
        state:
          await playerState(user)
      });

    } catch (e) {
      console.error(
        '[DEADFALL] login:',
        e
      );

      res.status(500).json({
        error:
          'Login failed.'
      });
    }
  }
);

// ============================================================
// STATE
// ============================================================

app.get(
  '/api/state',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      res.json(
        await playerState(
          req.user
        )
      );
    } catch (e) {
      console.error(
        '[DEADFALL] state:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load player state.'
      });
    }
  }
);

// ============================================================
// BUILD
// ============================================================

app.post(
  '/api/action/build',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      const name = cleanText(
        req.body.name,
        40
      );

      if (!BUILDINGS.includes(name)) {
        return res.status(400).json({
          error:
            'Invalid building.'
        });
      }

      const [
        building,
        city
      ] = await Promise.all([
        Building.findOne({
          userId: req.user._id,
          name
        }),

        City.findOne({
          userId: req.user._id
        })
      ]);

      if (!building || !city) {
        return res.status(404).json({
          error:
            'Building or city not found.'
        });
      }

      if (building.level >= 99) {
        return res.status(400).json({
          error:
            'Building is already at maximum level.'
        });
      }

      const cost = {
        wood: 50 * building.level,
        metal: 30 * building.level
      };

      if (
        city.wood < cost.wood ||
        city.metal < cost.metal
      ) {
        return res.status(400).json({
          error:
            `Need ${cost.wood} wood and ${cost.metal} metal.`
        });
      }

      city.wood -= cost.wood;
      city.metal -= cost.metal;

      building.level += 1;

      city.threat =
        Math.max(
          0,
          city.threat - 1
        );

      city.updatedAt =
        new Date();

      req.user.xp += 50;

      processLevel(req.user);

      await Promise.all([
        city.save(),
        building.save(),
        req.user.save()
      ]);

      sendUser(
        req.user._id,
        'world:update',
        {
          reason: 'build'
        }
      );

      res.json({
        ok: true,
        state:
          await playerState(
            req.user
          )
      });

    } catch (e) {
      console.error(
        '[DEADFALL] build:',
        e
      );

      res.status(500).json({
        error:
          'Build action failed.'
      });
    }
  }
);

// ============================================================
// COMBAT
// ============================================================

app.post(
  '/api/action/combat',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      const [
        city,
        army
      ] = await Promise.all([
        City.findOne({
          userId: req.user._id
        }),

        Army.find({
          userId: req.user._id
        })
      ]);

      if (!city) {
        return res.status(404).json({
          error:
            'City not found.'
        });
      }

      const strength =
        army.reduce(
          (sum, unit) =>
            sum + Number(unit.count || 0),
          0
        );

      if (strength < 1) {
        return res.status(400).json({
          error:
            'No troops available.'
        });
      }

      const kills = Math.max(
        1,
        Math.min(
          25,
          Math.floor(
            strength *
              (
                0.15 +
                Math.random() * 0.2
              )
          )
        )
      );

      const loss = Math.min(
        strength,
        Math.floor(
          kills *
            (
              0.08 +
              Math.random() * 0.1
            )
        )
      );

      let remaining = loss;

      for (const unit of army) {
        const take =
          Math.min(
            unit.count,
            remaining
          );

        unit.count -= take;

        remaining -= take;

        await unit.save();

        if (remaining <= 0) {
          break;
        }
      }

      city.threat =
        Math.max(
          0,
          city.threat - 3
        );

      city.food =
        Math.max(
          0,
          city.food - 10
        );

      await city.save();

      req.user.kills += kills;

      req.user.xp +=
        kills * 15;

      processLevel(req.user);

      await req.user.save();

      // Keep global horde pressure moving.
      if (world.horde > 0) {
        world.horde =
          Math.max(
            0,
            world.horde - kills
          );

        world.updatedAt =
          new Date();

        io.emit(
          'world:state',
          worldState()
        );
      }

      sendUser(
        req.user._id,
        'world:update',
        {
          reason: 'combat'
        }
      );

      res.json({
        ok: true,
        kills,
        loss,
        state:
          await playerState(
            req.user
          )
      });

    } catch (e) {
      console.error(
        '[DEADFALL] combat:',
        e
      );

      res.status(500).json({
        error:
          'Combat failed.'
      });
    }
  }
);

// ============================================================
// MISSIONS
// ============================================================
//
// FIXED:
// - Prevents missing-city crash.
// - Calculates live progress.
// - Synchronizes stored progress.
// - Gives rewards safely.
// - Returns useful mission data.
// ============================================================

app.post(
  '/api/action/mission',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      const code = cleanText(
        req.body.code,
        40
      );

      const def =
        MISSION_DEFS.find(
          mission =>
            mission.code === code
        );

      if (!def) {
        return res.status(404).json({
          error:
            'Mission not found.'
        });
      }

      const mission =
        await Mission.findOne({
          userId: req.user._id,
          code
        });

      if (!mission) {
        return res.status(404).json({
          error:
            'Mission not found.'
        });
      }

      if (mission.claimed) {
        return res.status(400).json({
          error:
            'Mission already claimed.'
        });
      }

      const city =
        await City.findOne({
          userId: req.user._id
        });

      if (!city) {
        return res.status(404).json({
          error:
            'City not found.'
        });
      }

      const progress =
        await calculateMissionProgress(
          req.user,
          city
        );

      const currentProgress =
        clampInt(
          progress[code] || 0,
          0,
          100000000
        );

      mission.progress =
        currentProgress;

      if (
        currentProgress <
        def.target
      ) {
        await mission.save();

        return res.status(400).json({
          error:
            'Mission not complete.',
          progress:
            currentProgress,
          target:
            def.target
        });
      }

      // Mark as claimed.
      mission.claimed = true;

      // XP reward.
      req.user.xp +=
        Number(
          def.reward?.xp || 0
        );

      // Resource rewards.
      for (
        const resource of [
          'food',
          'wood',
          'metal',
          'fuel'
        ]
      ) {
        const reward =
          Number(
            def.reward?.[resource] || 0
          );

        if (reward > 0) {
          city[resource] =
            clampInt(
              Number(city[resource] || 0) +
                reward,
              0,
              100000000
            );
        }
      }

      processLevel(req.user);

      city.updatedAt =
        new Date();

      await Promise.all([
        mission.save(),
        req.user.save(),
        city.save()
      ]);

      sendUser(
        req.user._id,
        'world:update',
        {
          reason: 'mission'
        }
      );

      res.json({
        ok: true,

        mission: {
          code: def.code,
          title: def.title,
          progress: currentProgress,
          target: def.target,
          claimed: true
        },

        reward: def.reward,

        state:
          await playerState(
            req.user
          )
      });

    } catch (e) {
      console.error(
        '[DEADFALL] mission:',
        e
      );

      res.status(500).json({
        error:
          'Mission action failed.'
      });
    }
  }
);

// ============================================================
// RANKINGS
// ============================================================

app.get(
  '/api/rankings',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      const players =
        await User.find({
          banned: false
        })
          .sort({
            kills: -1,
            xp: -1
          })
          .limit(100)
          .select(
            'name level kills xp role'
          )
          .lean();

      res.json({
        players
      });

    } catch (e) {
      console.error(
        '[DEADFALL] rankings:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load rankings.'
      });
    }
  }
);

// ============================================================
// WORLD MAP
// ============================================================

app.get(
  '/api/map',
  auth,
  dbRequired,
  async (req, res) => {
    try {
      const cities =
        await City.find()
          .select(
            'userId cityName wall threat'
          )
          .limit(500)
          .lean();

      const users =
        await User.find({
          _id: {
            $in:
              cities.map(
                city =>
                  city.userId
              )
          }
        })
          .select(
            'name level'
          )
          .lean();

      const by =
        new Map(
          users.map(
            user => [
              String(user._id),
              user
            ]
          )
        );

      res.json({
        points:
          cities.map(
            (city, index) => ({
              id: String(
                city.userId
              ),

              name:
                city.cityName ||
                'New Haven',

              owner:
                by.get(
                  String(city.userId)
                )?.name ||
                'Unknown',

              level:
                by.get(
                  String(city.userId)
                )?.level ||
                1,

              wall:
                city.wall,

              threat:
                city.threat,

              x:
                10 +
                (index * 37) % 80,

              y:
                12 +
                (index * 61) % 76
            })
          )
      });

    } catch (e) {
      console.error(
        '[DEADFALL] map:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load world map.'
      });
    }
  }
);

// ============================================================
// ADMIN — PLAYERS
// ============================================================

app.get(
  '/api/admin/players',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const players =
        await User.find()
          .sort({
            lastSeen: -1
          })
          .select('-password')
          .limit(2000)
          .lean();

      res.json({
        players
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin players:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load players.'
      });
    }
  }
);

// ============================================================
// ADMIN — SINGLE PLAYER
// ============================================================

app.get(
  '/api/admin/player/:playerId',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.playerId
        ).select('-password');

      if (!user) {
        return res.status(404).json({
          error:
            'Player not found.'
        });
      }

      res.json({
        state:
          await playerState(user)
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin player:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load player.'
      });
    }
  }
);

// ============================================================
// ADMIN — LOGS
// ============================================================

app.get(
  '/api/admin/logs',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const logs =
        await AdminLog.find()
          .sort({
            createdAt: -1
          })
          .limit(500)
          .lean();

      res.json({
        logs
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin logs:',
        e
      );

      res.status(500).json({
        error:
          'Failed to load audit logs.'
      });
    }
  }
);

// ============================================================
// ADMIN — GIVE
// ============================================================

app.post(
  '/api/admin/give',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const field =
        cleanText(
          req.body.field,
          20
        );

      const amount =
        clampInt(
          req.body.amount,
          -100000000,
          100000000
        );

      const user =
        await User.findById(
          targetId
        );

      if (!user) {
        return res.status(404).json({
          error:
            'Player not found.'
        });
      }

      if (
        ['xp', 'kills', 'level']
          .includes(field)
      ) {
        const min =
          field === 'level'
            ? 1
            : 0;

        user[field] =
          clampInt(
            Number(
              user[field] || 0
            ) + amount,
            min,
            100000000
          );

        processLevel(user);

        await user.save();

      } else if (
        [
          'food',
          'wood',
          'metal',
          'fuel',
          'wall',
          'threat'
        ].includes(field)
      ) {
        const city =
          await City.findOne({
            userId: targetId
          });

        if (!city) {
          return res.status(404).json({
            error:
              'City not found.'
          });
        }

        const max =
          [
            'wall',
            'threat'
          ].includes(field)
            ? 100
            : 100000000;

        city[field] =
          clampInt(
            Number(
              city[field] || 0
            ) + amount,
            0,
            max
          );

        city.updatedAt =
          new Date();

        await city.save();

      } else {
        return res.status(400).json({
          error:
            'Unsupported field.'
        });
      }

      await logAdmin(
        req.user._id,
        'GIVE',
        targetId,
        {
          field,
          amount
        }
      );

      sendUser(
        targetId,
        'world:update',
        {
          reason: 'admin'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin give:',
        e
      );

      res.status(500).json({
        error:
          'Admin give failed.'
      });
    }
  }
);

// ============================================================
// ADMIN — SET PLAYER
// ============================================================

app.post(
  '/api/admin/set-player',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const user =
        await User.findById(
          targetId
        );

      if (!user) {
        return res.status(404).json({
          error:
            'Player not found.'
        });
      }

      if (
        req.body.name !== undefined
      ) {
        user.name =
          cleanText(
            req.body.name,
            30
          ) ||
          user.name;
      }

      if (
        req.body.role !== undefined
      ) {
        const role =
          String(
            req.body.role
          );

        if (
          ['player', 'admin']
            .includes(role)
        ) {
          user.role = role;
        }
      }

      if (
        req.body.banned !== undefined
      ) {
        user.banned =
          Boolean(
            req.body.banned
          );
      }

      for (
        const field of [
          'xp',
          'kills',
          'level'
        ]
      ) {
        if (
          req.body[field] !== undefined
        ) {
          user[field] =
            clampInt(
              req.body[field],
              field === 'level'
                ? 1
                : 0,
              100000000
            );
        }
      }

      processLevel(user);

      await user.save();

      await logAdmin(
        req.user._id,
        'SET_PLAYER',
        targetId,
        {
          role: user.role,
          banned: user.banned,
          name: user.name,
          xp: user.xp,
          level: user.level,
          kills: user.kills
        }
      );

      if (user.banned) {
        sendUser(
          targetId,
          'account:disabled'
        );
      } else {
        sendUser(
          targetId,
          'world:update',
          {
            reason: 'admin'
          }
        );
      }

      res.json({
        ok: true,
        player:
          safeUser(user)
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin set-player:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update player.'
      });
    }
  }
);

// ============================================================
// ADMIN — SET CITY
// ============================================================

app.post(
  '/api/admin/set-city',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const city =
        await City.findOne({
          userId: targetId
        });

      if (!city) {
        return res.status(404).json({
          error:
            'City not found.'
        });
      }

      for (
        const field of [
          'food',
          'wood',
          'metal',
          'fuel'
        ]
      ) {
        if (
          req.body[field] !== undefined
        ) {
          city[field] =
            clampInt(
              req.body[field],
              0,
              100000000
            );
        }
      }

      for (
        const field of [
          'wall',
          'threat'
        ]
      ) {
        if (
          req.body[field] !== undefined
        ) {
          city[field] =
            clampInt(
              req.body[field],
              0,
              100
            );
        }
      }

      if (
        req.body.cityName !== undefined
      ) {
        city.cityName =
          cleanText(
            req.body.cityName,
            40
          ) ||
          'New Haven';
      }

      city.updatedAt =
        new Date();

      await city.save();

      await logAdmin(
        req.user._id,
        'SET_CITY',
        targetId,
        req.body
      );

      sendUser(
        targetId,
        'world:update',
        {
          reason: 'admin'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin set-city:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update city.'
      });
    }
  }
);

// ============================================================
// ADMIN — SET BUILDING
// ============================================================

app.post(
  '/api/admin/set-building',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const name =
        cleanText(
          req.body.name,
          40
        );

      if (!BUILDINGS.includes(name)) {
        return res.status(400).json({
          error:
            'Invalid building.'
        });
      }

      const building =
        await Building.findOne({
          userId: targetId,
          name
        });

      if (!building) {
        return res.status(404).json({
          error:
            'Building not found.'
        });
      }

      building.level =
        clampInt(
          req.body.level,
          1,
          99
        );

      await building.save();

      await logAdmin(
        req.user._id,
        'SET_BUILDING',
        targetId,
        {
          name,
          level:
            building.level
        }
      );

      sendUser(
        targetId,
        'world:update',
        {
          reason: 'admin'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin set-building:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update building.'
      });
    }
  }
);

// ============================================================
// ADMIN — SET ARMY
// ============================================================

app.post(
  '/api/admin/set-army',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const type =
        cleanText(
          req.body.type,
          30
        );

      if (!ARMIES.includes(type)) {
        return res.status(400).json({
          error:
            'Invalid army type.'
        });
      }

      const army =
        await Army.findOne({
          userId: targetId,
          type
        });

      if (!army) {
        return res.status(404).json({
          error:
            'Army unit not found.'
        });
      }

      army.count =
        clampInt(
          req.body.count,
          0,
          100000
        );

      await army.save();

      await logAdmin(
        req.user._id,
        'SET_ARMY',
        targetId,
        {
          type,
          count:
            army.count
        }
      );

      sendUser(
        targetId,
        'world:update',
        {
          reason: 'admin'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin set-army:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update army.'
      });
    }
  }
);

// ============================================================
// ADMIN — RESET PLAYER
// ============================================================

app.post(
  '/api/admin/reset-player',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      const user =
        await User.findById(
          targetId
        );

      if (!user) {
        return res.status(404).json({
          error:
            'Player not found.'
        });
      }

      user.xp = 0;
      user.level = 1;
      user.kills = 0;

      await Promise.all([
        user.save(),

        City.deleteOne({
          userId: targetId
        }),

        Building.deleteMany({
          userId: targetId
        }),

        Army.deleteMany({
          userId: targetId
        }),

        Mission.deleteMany({
          userId: targetId
        })
      ]);

      await ensurePlayer(user);

      await logAdmin(
        req.user._id,
        'RESET_PLAYER',
        targetId,
        {}
      );

      sendUser(
        targetId,
        'world:update',
        {
          reason: 'reset'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin reset:',
        e
      );

      res.status(500).json({
        error:
          'Failed to reset player.'
      });
    }
  }
);

// ============================================================
// ADMIN — DELETE PLAYER
// ============================================================

app.post(
  '/api/admin/delete-player',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      if (
        targetId ===
        String(req.user._id)
      ) {
        return res.status(400).json({
          error:
            'You cannot delete yourself.'
        });
      }

      const user =
        await User.findById(
          targetId
        );

      if (!user) {
        return res.status(404).json({
          error:
            'Player not found.'
        });
      }

      sendUser(
        targetId,
        'account:disabled'
      );

      await Promise.all([
        User.deleteOne({
          _id: targetId
        }),

        City.deleteOne({
          userId: targetId
        }),

        Building.deleteMany({
          userId: targetId
        }),

        Army.deleteMany({
          userId: targetId
        }),

        Mission.deleteMany({
          userId: targetId
        })
      ]);

      await logAdmin(
        req.user._id,
        'DELETE_PLAYER',
        targetId,
        {}
      );

      res.json({
        ok: true
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin delete:',
        e
      );

      res.status(500).json({
        error:
          'Failed to delete player.'
      });
    }
  }
);


// ============================================================
// ADMIN — BAN / UNBAN PLAYER
// ============================================================

app.post(
  '/api/admin/ban',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      if (!targetId) {
        return res.status(400).json({
          error: 'Player ID is required.'
        });
      }

      const banned =
        Boolean(req.body.banned);

      const user =
        await User.findById(targetId);

      if (!user) {
        return res.status(404).json({
          error: 'Player not found.'
        });
      }

      // Don't allow an admin to accidentally ban themselves.
      if (
        String(user._id) ===
        String(req.user._id)
      ) {
        return res.status(400).json({
          error: 'You cannot ban yourself.'
        });
      }

      user.banned = banned;

      await user.save();

      await logAdmin(
        req.user._id,
        banned ? 'BAN_PLAYER' : 'UNBAN_PLAYER',
        targetId,
        {
          banned
        }
      );

      // Notify connected player immediately.
      sendUser(
        targetId,
        'account:banned',
        {
          banned
        }
      );

      res.json({
        ok: true,
        banned
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin ban:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update player ban status.'
      });
    }
  }
);


// ============================================================
// ADMIN — KICK PLAYER
// ============================================================

app.post(
  '/api/admin/kick',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {

      const targetId =
        cleanText(
          req.body.playerId,
          50
        );

      if (!targetId) {
        return res.status(400).json({
          error: 'Player ID is required.'
        });
      }

      const user =
        await User.findById(targetId);

      if (!user) {
        return res.status(404).json({
          error: 'Player not found.'
        });
      }

      // Find the player's active socket/session.
      const socket =
        onlinePlayers.get(
          String(targetId)
        );

      if (!socket) {
        return res.status(400).json({
          error: 'Player is not currently online.'
        });
      }

      socket.emit(
        'admin:kick',
        {
          reason: 'Removed by administrator.'
        }
      );

      socket.disconnect(true);

      await logAdmin(
        req.user._id,
        'KICK_PLAYER',
        targetId,
        {
          reason: 'Administrator kick'
        }
      );

      res.json({
        ok: true
      });

    } catch (e) {

      console.error(
        '[DEADFALL] admin kick:',
        e
      );

      res.status(500).json({
        error:
          'Failed to kick player.'
      });

    }
  }
);


// ============================================================
// ADMIN — HORDE
// ============================================================

app.post(
  '/api/admin/horde',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const amount =
        clampInt(
          req.body.amount,
          1,
          100000
        );

      world.horde += amount;

      world.threat =
        Math.min(
          100,
          world.threat +
            Math.ceil(
              amount / 25
            )
        );

      world.updatedAt =
        new Date();

      broadcastWorld(
        'horde',
        {
          amount,
          total:
            world.horde,
          threat:
            world.threat
        }
      );

      await logAdmin(
        req.user._id,
        'HORDE',
        'WORLD',
        {
          amount
        }
      );

      res.json({
        ok: true,
        world:
          worldState()
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin horde:',
        e
      );

      res.status(500).json({
        error:
          'Failed to spawn horde.'
      });
    }
  }
);

// ============================================================
// ADMIN — WORLD CONTROL
// ============================================================

app.post(
  '/api/admin/world',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      if (
        req.body.threat !== undefined
      ) {
        world.threat =
          clampInt(
            req.body.threat,
            0,
            100
          );
      }

      if (
        ['DAY', 'NIGHT', 'DUSK']
          .includes(
            String(
              req.body.phase || ''
            )
          )
      ) {
        world.phase =
          String(
            req.body.phase
          );
      }

      if (
        [
          'CLEAR',
          'FOG',
          'RAIN',
          'STORM'
        ].includes(
          String(
            req.body.weather || ''
          )
        )
      ) {
        world.weather =
          String(
            req.body.weather
          );
      }

      world.updatedAt =
        new Date();

      broadcastWorld(
        'world_control',
        {
          world:
            worldState()
        }
      );

      await logAdmin(
        req.user._id,
        'WORLD_CONTROL',
        'WORLD',
        req.body
      );

      res.json({
        ok: true,
        world:
          worldState()
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin world:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update world.'
      });
    }
  }
);

// ============================================================
// ADMIN — BROADCAST
// ============================================================

app.post(
  '/api/admin/broadcast',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      const title =
        cleanText(
          req.body.title ||
            'EMERGENCY BROADCAST',
          80
        );

      const text =
        cleanText(
          req.body.message ||
            req.body.text,
          500
        );

      if (!text) {
        return res.status(400).json({
          error:
            'Message required.'
        });
      }

      world.event = {
        title,
        text,
        at:
          new Date().toISOString()
      };

      broadcastWorld(
        'broadcast',
        {
          title,
          text,
          at:
            world.event.at
        }
      );

      await logAdmin(
        req.user._id,
        'BROADCAST',
        'WORLD',
        {
          title,
          text
        }
      );

      res.json({
        ok: true,
        event:
          world.event
      });

    } catch (e) {
      console.error(
        '[DEADFALL] admin broadcast:',
        e
      );

      res.status(500).json({
        error:
          'Failed to send broadcast.'
      });
    }
  }
);

// ============================================================
// ADMIN — MAINTENANCE
// ============================================================

app.post(
  '/api/admin/maintenance',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      world.maintenance =
        Boolean(
          req.body.enabled
        );

      world.updatedAt =
        new Date();

      broadcastWorld(
        'maintenance',
        {
          enabled:
            world.maintenance
        }
      );

      await logAdmin(
        req.user._id,
        'MAINTENANCE',
        'WORLD',
        {
          enabled:
            world.maintenance
        }
      );

      res.json({
        ok: true,
        enabled:
          world.maintenance
      });

    } catch (e) {
      console.error(
        '[DEADFALL] maintenance:',
        e
      );

      res.status(500).json({
        error:
          'Failed to update maintenance mode.'
      });
    }
  }
);

// ============================================================
// ADMIN — CLEAR EVENT
// ============================================================

app.post(
  '/api/admin/clear-event',
  auth,
  dbRequired,
  admin,
  async (req, res) => {
    try {
      world.event = null;

      world.updatedAt =
        new Date();

      broadcastWorld(
        'world_control',
        {
          world:
            worldState()
        }
      );

      await logAdmin(
        req.user._id,
        'CLEAR_EVENT',
        'WORLD',
        {}
      );

      res.json({
        ok: true,
        world:
          worldState()
      });

    } catch (e) {
      console.error(
        '[DEADFALL] clear event:',
        e
      );

      res.status(500).json({
        error:
          'Failed to clear event.'
      });
    }
  }
);

// ============================================================
// SOCKET.IO
// ============================================================

io.on(
  'connection',
  socket => {

    console.log(
      `[DEADFALL SOCKET] Connected: ${socket.id}`
    );

    // Send world immediately.
    socket.emit(
      'world:state',
      worldState()
    );

    socket.on(
      'join',
      async data => {
        try {
          if (!JWT_SECRET) {
            return;
          }

          const token =
            String(
              data?.token || ''
            );

          if (!token) {
            return;
          }

          const payload =
            jwt.verify(
              token,
              JWT_SECRET
            );

          const user =
            await User.findById(
              payload.id
            );

          if (
            !user ||
            user.banned
          ) {
            return;
          }

          const userId =
            String(
              user._id
            );

          socket.userId =
            userId;

          socket.join(
            `user:${userId}`
          );

          online.set(
            socket.id,
            userId
          );

          if (
            !socketsByUser.has(
              userId
            )
          ) {
            socketsByUser.set(
              userId,
              new Set()
            );
          }

          socketsByUser
            .get(userId)
            .add(socket.id);

          socket.emit(
            'world:state',
            worldState()
          );

          io.emit(
            'world:presence',
            {
              online:
                online.size
            }
          );

          console.log(
            `[DEADFALL SOCKET] ${user.name} joined (${socket.id})`
          );

        } catch (e) {
          console.warn(
            '[DEADFALL SOCKET] Join failed:',
            e.message
          );
        }
      }
    );

    socket.on(
      'disconnect',
      reason => {
        const userId =
          online.get(
            socket.id
          );

        online.delete(
          socket.id
        );

        if (
          userId &&
          socketsByUser.has(
            userId
          )
        ) {
          const set =
            socketsByUser.get(
              userId
            );

          set.delete(
            socket.id
          );

          if (!set.size) {
            socketsByUser.delete(
              userId
            );
          }
        }

        io.emit(
          'world:presence',
          {
            online:
              online.size
          }
        );

        console.log(
          `[DEADFALL SOCKET] Disconnected: ${socket.id} (${reason})`
        );
      }
    );
  }
);

// ============================================================
// WORLD TICK
// ============================================================

let tickBusy = false;

setInterval(
  async () => {

    if (
      tickBusy ||
      mongoose.connection.readyState !== 1
    ) {
      return;
    }

    tickBusy = true;

    try {
      const cities =
        await City.find();

      for (
        const city of cities
      ) {

        city.food =
          Math.min(
            100000,
            city.food + 10
          );

        city.wood =
          Math.min(
            100000,
            city.wood + 8
          );

        city.metal =
          Math.min(
            100000,
            city.metal + 5
          );

        city.fuel =
          Math.min(
            100000,
            city.fuel + 1
          );

        if (
          world.horde > 0
        ) {
          city.threat =
            Math.min(
              100,
              city.threat + 1
            );

          if (
            Math.random() <
            0.08
          ) {
            city.wall =
              Math.max(
                0,
                city.wall - 1
              );
          }
        }

        city.updatedAt =
          new Date();

        await city.save();
      }

      // Global threat movement.
      if (
        Math.random() < 0.35
      ) {
        world.threat =
          Math.min(
            100,
            world.threat + 1
          );
      } else {
        world.threat =
          Math.max(
            0,
            world.threat - 1
          );
      }

      // Horde naturally decreases.
      if (
        world.horde > 0
      ) {
        world.horde =
          Math.max(
            0,
            world.horde -
              Math.max(
                1,
                Math.ceil(
                  world.horde *
                    0.02
                )
              )
          );
      }

      world.updatedAt =
        new Date();

      io.emit(
        'world:tick',
        {
          world:
            worldState()
        }
      );

    } catch (e) {
      console.error(
        '[DEADFALL] tick:',
        e
      );
    } finally {
      tickBusy = false;
    }

  },
  60000
);

// ============================================================
// STATIC FRONTEND
// ============================================================

app.use(
  express.static(
    path.join(
      __dirname,
      'public'
    ),
    {
      extensions: ['html']
    }
  )
);

// ============================================================
// SPA FALLBACK
// ============================================================

app.get(
  '*',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'public',
        'index.html'
      )
    );
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (err, req, res, next) => {
    console.error(
      '[DEADFALL] Unhandled server error:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      error:
        'Internal server error.'
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

server.listen(
  PORT,
  '0.0.0.0',
  async () => {

    console.log(
      `[DEADFALL] Server listening on 0.0.0.0:${PORT}`
    );

    console.log(
      `[DEADFALL] Allowed origins: ${allowedOrigins.join(', ')}`
    );

    console.log(
      '[DEADFALL] Socket.IO enabled'
    );

    if (
      !MONGODB_URI ||
      !JWT_SECRET
    ) {
      console.warn(
        '[DEADFALL] Database/auth startup skipped because environment variables are missing.'
      );

      return;
    }

    try {

      await mongoose.connect(
        MONGODB_URI,
        {
          serverSelectionTimeoutMS: 10000
        }
      );

      console.log(
        '[DEADFALL] MongoDB connected'
      );

      // --------------------------------------------------------
      // INITIAL ADMIN
      // --------------------------------------------------------

      if (
        process.env.ADMIN_EMAIL &&
        process.env.ADMIN_PASSWORD
      ) {

        const email =
          process.env.ADMIN_EMAIL
            .trim()
            .toLowerCase();

        let adminUser =
          await User.findOne({
            email
          });

        if (!adminUser) {

          adminUser =
            await User.create({
              email,
              name: 'COMMAND',
              role: 'admin',
              password:
                await bcrypt.hash(
                  process.env.ADMIN_PASSWORD,
                  12
                )
            });

          console.log(
            `[DEADFALL] Initial admin created: ${email}`
          );

        } else if (
          adminUser.role !==
          'admin'
        ) {

          adminUser.role =
            'admin';

          await adminUser.save();

          console.log(
            `[DEADFALL] Promoted admin: ${email}`
          );
        }
      }

    } catch (e) {

      console.error(
        '[DEADFALL] MongoDB connection failed:',
        e
      );
    }
  }
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown(
  signal
) {
  console.log(
    `[DEADFALL] ${signal} received. Shutting down...`
  );

  server.close(
    () => {
      console.log(
        '[DEADFALL] HTTP server closed.'
      );

      mongoose.connection.close(
        false
      )
      .then(() => {
        console.log(
          '[DEADFALL] MongoDB connection closed.'
        );

        process.exit(0);
      })
      .catch(() => {
        process.exit(0);
      });
    }
  );
}

process.on(
  'SIGTERM',
  () => shutdown('SIGTERM')
);

process.on(
  'SIGINT',
  () => shutdown('SIGINT')
);

process.on(
  'unhandledRejection',
  error => {
    console.error(
      '[DEADFALL] Unhandled promise rejection:',
      error
    );
  }
);

process.on(
  'uncaughtException',
  error => {
    console.error(
      '[DEADFALL] Uncaught exception:',
      error
    );
  }
);
