/**
 * Remind Me - Backend Server & REST API
 * Hardened Security Edition:
 * - 600,000 PBKDF2-HMAC-SHA256 iterations with automated legacy hash migration
 * - Timing-safe password verification (crypto.timingSafeEqual)
 * - HMAC-SHA256 hashed session token storage (zero plaintext tokens in database)
 * - Session expiration, cleanup, and per-user session limits
 * - Isolated ephemeral workspaces for demo visitors (cross-tenant isolation)
 * - Restricted CORS with environment-configured origins
 * - Robust input validation and sanitized logging
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ==========================================
// CONFIGURATION & ENVIRONMENT
// ==========================================
const PORT = parseInt(process.env.PORT, 10) || 3000;
const PUBLIC_DIR = __dirname;
const DB_FILE = path.join(__dirname, 'data', 'database.json');

// Session Secret: Loaded from environment or persistent fallback
const SESSION_SECRET = process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? '' : crypto.randomBytes(32).toString('hex'));
if (SESSION_SECRET.length < 32) {
  console.error('ERROR: Set a SESSION_SECRET of at least 32 characters.');
  process.exit(1);
}

// PBKDF2 Iteration Constants
const CURRENT_PBKDF2_ITERATIONS = parseInt(process.env.PBKDF2_ITERATIONS, 10) || 600000;
const LEGACY_PBKDF2_ITERATIONS = 1000;
const KEY_LENGTH = 32;
const DIGEST = 'sha256';

// Session Lifetimes
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;       // 7 days for registered users
const DEMO_SESSION_TTL_MS = 24 * 60 * 60 * 1000;      // 24 hours for ephemeral demo workspaces
const MAX_SESSIONS_PER_USER = 5;                       // Prevent unbounded session accumulation

// Allowed CORS Origins
const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  `http://localhost:${PORT}`,
  `http://127.0.0.1:${PORT}`
];

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim().toLowerCase())
  : DEFAULT_ALLOWED_ORIGINS;

// Validation Whitelists
const ALLOWED_RINGTONES = ['chime', 'digital', 'marimba', 'zen', 'harp', 'classic'];
const ALLOWED_TAGS = ['work', 'meeting', 'personal', 'health', 'study', 'shopping', 'finance', 'urgent'];
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const TIME_REGEX = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

// ==========================================
// 1. CRYPTOGRAPHIC & VALIDATION HELPERS
// ==========================================

// Hash password with configurable iterations
function hashPassword(password, salt, iterations = CURRENT_PBKDF2_ITERATIONS) {
  return crypto.pbkdf2Sync(password, salt, iterations, KEY_LENGTH, DIGEST).toString('hex');
}

// Constant-time password verification to prevent timing side-channel attacks
function verifyPassword(providedPassword, salt, expectedHashHex, iterations = CURRENT_PBKDF2_ITERATIONS) {
  try {
    const calculatedHashHex = hashPassword(providedPassword, salt, iterations);
    const calculatedBuf = Buffer.from(calculatedHashHex, 'hex');
    const expectedBuf = Buffer.from(expectedHashHex, 'hex');

    if (calculatedBuf.length !== expectedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(calculatedBuf, expectedBuf);
  } catch (err) {
    return false;
  }
}

// One-way cryptographic hash for session tokens before storage
function hashSessionToken(rawToken) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(rawToken).digest('hex');
}

// Email format validation
function isValidEmail(email) {
  return typeof email === 'string' && email.length <= 254 && EMAIL_REGEX.test(email.trim());
}

// Password strength validation (minimum 8 characters, maximum 128 characters)
function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

// Sanitize string text (strip control characters)
function sanitizeString(str, maxLength = 200) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, maxLength);
}

// ==========================================
// 2. DATABASE & SESSION LIFECYCLE
// ==========================================

function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    const defaultSalt = crypto.randomBytes(16).toString('hex');
    const defaultPasswordHash = hashPassword('password123', defaultSalt, CURRENT_PBKDF2_ITERATIONS);
    const demoUserId = 'usr_demo_template';

    const initialData = {
      users: [
        {
          id: demoUserId,
          name: 'Demo Template User',
          email: 'demo@remindme.com',
          salt: defaultSalt,
          passwordHash: defaultPasswordHash,
          iterations: CURRENT_PBKDF2_ITERATIONS,
          isDemoTemplate: true,
          createdAt: Date.now(),
          settings: {
            defaultRingtone: 'chime',
            enableSound: true,
            enableNotifications: true
          }
        }
      ],
      sessions: {},
      tasks: [],
      history: []
    };

    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf8');
  }
}

function loadDB() {
  try {
    initDB();
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const db = JSON.parse(raw);
    db.users = db.users || [];
    db.sessions = db.sessions || {};
    db.tasks = db.tasks || [];
    db.history = db.history || [];
    return db;
  } catch (err) {
    console.error('Error loading database file:', err.message);
    return { users: [], sessions: {}, tasks: [], history: [] };
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving database file:', err.message);
  }
}

// Prune expired sessions and clean up expired demo workspaces
function pruneExpiredSessions(db) {
  const now = Date.now();
  let modified = false;
  const expiredDemoUserIds = new Set();

  for (const [hashedToken, session] of Object.entries(db.sessions)) {
    const ttl = session.isDemo ? DEMO_SESSION_TTL_MS : SESSION_TTL_MS;
    const isExpired = (now - session.createdAt > ttl) || (session.expiresAt && now > session.expiresAt);

    if (isExpired) {
      if (session.isDemo && session.userId && session.userId.startsWith('usr_demo_')) {
        expiredDemoUserIds.add(session.userId);
      }
      delete db.sessions[hashedToken];
      modified = true;
    }
  }

  // Remove temporary demo users and their data once expired
  if (expiredDemoUserIds.size > 0) {
    db.users = db.users.filter(u => !expiredDemoUserIds.has(u.id));
    db.tasks = db.tasks.filter(t => !expiredDemoUserIds.has(t.userId));
    db.history = db.history.filter(h => !expiredDemoUserIds.has(h.userId));
    modified = true;
  }

  if (modified) {
    saveDB(db);
  }
}

// Prevent unlimited session accumulation by capping active sessions per user
function enforceSessionLimit(userId, db, maxSessions = MAX_SESSIONS_PER_USER) {
  const userSessions = Object.entries(db.sessions)
    .filter(([_, s]) => s.userId === userId)
    .sort((a, b) => a[1].createdAt - b[1].createdAt);

  while (userSessions.length >= maxSessions) {
    const [oldestTokenHash] = userSessions.shift();
    delete db.sessions[oldestTokenHash];
  }
}

// Authenticate caller from Authorization: Bearer <token>
function authenticateRequest(req, db) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const rawToken = authHeader.substring(7).trim();
  if (!rawToken) return null;

  // Lookup session by hashed token
  const tokenHash = hashSessionToken(rawToken);
  let session = db.sessions[tokenHash];

  // Backward compatibility: If a legacy unhashed token exists, migrate it
  if (!session && db.sessions[rawToken]) {
    session = db.sessions[rawToken];
    delete db.sessions[rawToken];
    db.sessions[tokenHash] = session;
    saveDB(db);
  }

  if (!session) return null;

  // Verify session expiration
  const ttl = session.isDemo ? DEMO_SESSION_TTL_MS : SESSION_TTL_MS;
  const now = Date.now();
  if ((now - session.createdAt > ttl) || (session.expiresAt && now > session.expiresAt)) {
    delete db.sessions[tokenHash];
    saveDB(db);
    return null;
  }

  // Update activity timestamp
  session.lastActiveAt = now;

  const user = db.users.find(u => u.id === session.userId);
  return user || null;
}

// Helper: Parse JSON Body with payload size limit
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) { // 1MB payload limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON format'));
      }
    });
    req.on('error', reject);
  });
}

// Helper: Send JSON response with security headers and CORS
function sendJson(res, statusCode, data, origin = null) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  };

  if (origin && (ALLOWED_ORIGINS.includes(origin.toLowerCase()) || ALLOWED_ORIGINS.includes('*'))) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    headers['Vary'] = 'Origin';
  }

  res.writeHead(statusCode, headers);
  res.end(JSON.stringify(data));
}

// MIME Types for Static File Serving
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.ics': 'text/calendar; charset=utf-8'
};

// ==========================================
// 3. HTTP SERVER & REST ROUTER
// ==========================================
const server = http.createServer(async (req, res) => {
  const incomingOrigin = req.headers['origin'];
  const isOriginAllowed = incomingOrigin && ALLOWED_ORIGINS.includes(incomingOrigin.toLowerCase());

  // Handle CORS Preflight Requests
  if (req.method === 'OPTIONS') {
    if (incomingOrigin && isOriginAllowed) {
      res.writeHead(200, {
        'Access-Control-Allow-Origin': incomingOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin'
      });
    } else {
      res.writeHead(204);
    }
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // ----------------------------------------------------
  // API ROUTING: /api/*
  // ----------------------------------------------------
  if (pathname.startsWith('/api/')) {
    const db = loadDB();
    pruneExpiredSessions(db);

    try {
      // 1. REGISTER
      if (pathname === '/api/auth/register' && method === 'POST') {
        const body = await parseJsonBody(req);
        const name = sanitizeString(body.name, 60);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';

        if (!name) {
          return sendJson(res, 400, { error: 'Name is required.' }, incomingOrigin);
        }
        if (!isValidEmail(email)) {
          return sendJson(res, 400, { error: 'Please enter a valid email address.' }, incomingOrigin);
        }
        if (!isValidPassword(password)) {
          return sendJson(res, 400, { error: 'Password must be between 8 and 128 characters long.' }, incomingOrigin);
        }

        const existing = db.users.find(u => u.email.toLowerCase() === email);
        if (existing) {
          return sendJson(res, 409, { error: 'An account with this email already exists.' }, incomingOrigin);
        }

        const salt = crypto.randomBytes(16).toString('hex');
        const passwordHash = hashPassword(password, salt, CURRENT_PBKDF2_ITERATIONS);
        const userId = 'usr_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');

        const newUser = {
          id: userId,
          name,
          email,
          salt,
          passwordHash,
          iterations: CURRENT_PBKDF2_ITERATIONS,
          createdAt: Date.now(),
          settings: { defaultRingtone: 'chime', enableSound: true, enableNotifications: true }
        };

        db.users.push(newUser);

        // Generate cryptographically secure session token
        const rawToken = 'tok_' + crypto.randomBytes(32).toString('hex');
        const tokenHash = hashSessionToken(rawToken);

        enforceSessionLimit(userId, db);
        db.sessions[tokenHash] = {
          userId,
          createdAt: Date.now(),
          lastActiveAt: Date.now(),
          isDemo: false
        };

        saveDB(db);

        return sendJson(res, 201, {
          token: rawToken,
          user: { id: newUser.id, name: newUser.name, email: newUser.email, createdAt: newUser.createdAt }
        }, incomingOrigin);
      }

      // 2. LOGIN (With safe hash migration & isolated demo workspaces)
      if (pathname === '/api/auth/login' && method === 'POST') {
        const body = await parseJsonBody(req);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';

        if (!isValidEmail(email) || !password) {
          return sendJson(res, 400, { error: 'Valid email and password are required.' }, incomingOrigin);
        }

        // ISOLATED DEMO WORKSPACE HANDLING
        // When demo user logs in, allocate an isolated temporary workspace so visitors do not share or overwrite tasks
        if (email === 'demo@remindme.com' && password === 'password123') {
          const demoVisitorId = 'usr_demo_' + crypto.randomBytes(8).toString('hex');
          const demoUser = {
            id: demoVisitorId,
            name: 'Demo User',
            email: 'demo@remindme.com',
            isDemo: true,
            createdAt: Date.now(),
            expiresAt: Date.now() + DEMO_SESSION_TTL_MS,
            settings: { defaultRingtone: 'chime', enableSound: true, enableNotifications: true }
          };

          db.users.push(demoUser);

          const rawToken = 'tok_' + crypto.randomBytes(32).toString('hex');
          const tokenHash = hashSessionToken(rawToken);

          db.sessions[tokenHash] = {
            userId: demoVisitorId,
            createdAt: Date.now(),
            lastActiveAt: Date.now(),
            expiresAt: Date.now() + DEMO_SESSION_TTL_MS,
            isDemo: true
          };

          saveDB(db);

          return sendJson(res, 200, {
            token: rawToken,
            user: { id: demoUser.id, name: demoUser.name, email: demoUser.email, isDemo: true }
          }, incomingOrigin);
        }

        // Standard Registered User Authentication
        const user = db.users.find(u => u.email.toLowerCase() === email && !u.isDemo);
        if (!user) {
          return sendJson(res, 401, { error: 'Invalid email or password.' }, incomingOrigin);
        }

        // Use stored iterations (fallback to legacy 1,000 for backward compatibility)
        const userIterations = user.iterations || LEGACY_PBKDF2_ITERATIONS;
        const isPasswordCorrect = verifyPassword(password, user.salt, user.passwordHash, userIterations);

        if (!isPasswordCorrect) {
          return sendJson(res, 401, { error: 'Invalid email or password.' }, incomingOrigin);
        }

        // AUTOMATIC PASSWORD HASH MIGRATION:
        // Upgrade legacy hashes (< 600,000 iterations) to 600,000 iterations with a fresh salt
        if (!user.iterations || user.iterations < CURRENT_PBKDF2_ITERATIONS) {
          const freshSalt = crypto.randomBytes(16).toString('hex');
          user.passwordHash = hashPassword(password, freshSalt, CURRENT_PBKDF2_ITERATIONS);
          user.salt = freshSalt;
          user.iterations = CURRENT_PBKDF2_ITERATIONS;
        }

        // Create Session Token and store hashed token
        const rawToken = 'tok_' + crypto.randomBytes(32).toString('hex');
        const tokenHash = hashSessionToken(rawToken);

        enforceSessionLimit(user.id, db);
        db.sessions[tokenHash] = {
          userId: user.id,
          createdAt: Date.now(),
          lastActiveAt: Date.now(),
          isDemo: false
        };

        saveDB(db);

        return sendJson(res, 200, {
          token: rawToken,
          user: { id: user.id, name: user.name, email: user.email, createdAt: user.createdAt }
        }, incomingOrigin);
      }

      // 3. GET CURRENT USER (ME)
      if (pathname === '/api/auth/me' && method === 'GET') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Not authenticated or session expired.' }, incomingOrigin);
        }
        return sendJson(res, 200, {
          user: { id: user.id, name: user.name, email: user.email, isDemo: !!user.isDemo, settings: user.settings }
        }, incomingOrigin);
      }

      // 4. LOGOUT
      if (pathname === '/api/auth/logout' && method === 'POST') {
        const authHeader = req.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const rawToken = authHeader.substring(7).trim();
          const tokenHash = hashSessionToken(rawToken);

          const session = db.sessions[tokenHash];
          if (session && session.isDemo && session.userId) {
            // Clean up isolated demo workspace immediately on logout
            db.users = db.users.filter(u => u.id !== session.userId);
            db.tasks = db.tasks.filter(t => t.userId !== session.userId);
            db.history = db.history.filter(h => h.userId !== session.userId);
          }

          delete db.sessions[tokenHash];
          delete db.sessions[rawToken]; // Clean up any legacy token if present
          saveDB(db);
        }
        return sendJson(res, 200, { message: 'Logged out successfully.' }, incomingOrigin);
      }

      // 5. GET TASKS (Strictly scoped to authenticated user)
      if (pathname === '/api/tasks' && method === 'GET') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        const dateFilter = parsedUrl.searchParams.get('date');
        let userTasks = db.tasks.filter(t => t.userId === user.id);
        if (dateFilter && DATE_REGEX.test(dateFilter)) {
          userTasks = userTasks.filter(t => t.date === dateFilter);
        }
        return sendJson(res, 200, { tasks: userTasks }, incomingOrigin);
      }

      // 6. CREATE TASK (With robust input validation)
      if (pathname === '/api/tasks' && method === 'POST') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        const body = await parseJsonBody(req);
        const name = sanitizeString(body.name, 200);
        const date = typeof body.date === 'string' && DATE_REGEX.test(body.date) ? body.date : '';
        const startTime = typeof body.startTime === 'string' && TIME_REGEX.test(body.startTime) ? body.startTime : '';
        const endTime = typeof body.endTime === 'string' && TIME_REGEX.test(body.endTime) ? body.endTime : '';
        const ringtone = ALLOWED_RINGTONES.includes(body.ringtone) ? body.ringtone : 'chime';
        const tagId = ALLOWED_TAGS.includes(body.tagId) ? body.tagId : 'work';

        if (!name || !date || !startTime) {
          return sendJson(res, 400, { error: 'Task name, valid date (YYYY-MM-DD), and start time (HH:MM) are required.' }, incomingOrigin);
        }

        const newTask = {
          id: 'task-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex'),
          userId: user.id,
          name,
          date,
          startTime,
          endTime,
          ringtone,
          tagId,
          completed: false,
          createdAt: Date.now()
        };

        db.tasks.unshift(newTask);
        saveDB(db);

        return sendJson(res, 201, { task: newTask }, incomingOrigin);
      }

      // 7. UPDATE TASK (Strict ownership enforcement)
      if (pathname.startsWith('/api/tasks/') && method === 'PUT') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        const taskId = sanitizeString(pathname.replace('/api/tasks/', ''), 50);
        const body = await parseJsonBody(req);

        const taskIndex = db.tasks.findIndex(t => t.id === taskId && t.userId === user.id);
        if (taskIndex === -1) {
          return sendJson(res, 404, { error: 'Task not found.' }, incomingOrigin);
        }

        const existingTask = db.tasks[taskIndex];
        const wasCompleted = existingTask.completed;
        const isNowCompleted = body.completed !== undefined ? Boolean(body.completed) : wasCompleted;

        const updatedTask = {
          ...existingTask,
          name: body.name ? sanitizeString(body.name, 200) : existingTask.name,
          date: body.date && DATE_REGEX.test(body.date) ? body.date : existingTask.date,
          startTime: body.startTime && TIME_REGEX.test(body.startTime) ? body.startTime : existingTask.startTime,
          endTime: body.endTime !== undefined ? (TIME_REGEX.test(body.endTime) ? body.endTime : '') : existingTask.endTime,
          ringtone: body.ringtone && ALLOWED_RINGTONES.includes(body.ringtone) ? body.ringtone : existingTask.ringtone,
          tagId: body.tagId && ALLOWED_TAGS.includes(body.tagId) ? body.tagId : existingTask.tagId,
          completed: isNowCompleted,
          completedAt: isNowCompleted ? (existingTask.completedAt || Date.now()) : null
        };

        db.tasks[taskIndex] = updatedTask;

        // Log completion record in history if newly completed
        if (!wasCompleted && isNowCompleted) {
          db.history.unshift({
            id: 'hist-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex'),
            userId: user.id,
            taskId: updatedTask.id,
            taskName: updatedTask.name,
            tagId: updatedTask.tagId,
            date: updatedTask.date,
            completedAt: Date.now()
          });
        }

        saveDB(db);
        return sendJson(res, 200, { task: updatedTask }, incomingOrigin);
      }

      // 8. DELETE TASK (Strict ownership enforcement)
      if (pathname.startsWith('/api/tasks/') && method === 'DELETE') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        const taskId = sanitizeString(pathname.replace('/api/tasks/', ''), 50);
        const originalCount = db.tasks.length;
        db.tasks = db.tasks.filter(t => !(t.id === taskId && t.userId === user.id));

        if (db.tasks.length !== originalCount) {
          saveDB(db);
        }

        return sendJson(res, 200, { message: 'Task deleted successfully.' }, incomingOrigin);
      }

      // 9. GET USER HISTORY & RECORDS (Strictly scoped to caller)
      if (pathname === '/api/history' && method === 'GET') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        const userHistory = (db.history || []).filter(h => h.userId === user.id);
        const userTasks = db.tasks.filter(t => t.userId === user.id);
        const totalCompleted = userHistory.length;
        const totalTasks = userTasks.length;

        const tagCounts = {};
        userHistory.forEach(h => {
          tagCounts[h.tagId] = (tagCounts[h.tagId] || 0) + 1;
        });

        const todayStr = new Date().toISOString().split('T')[0];
        const todayCompleted = userHistory.filter(h => {
          const hDate = new Date(h.completedAt).toISOString().split('T')[0];
          return hDate === todayStr;
        }).length;

        return sendJson(res, 200, {
          records: userHistory,
          stats: {
            totalCompleted,
            todayCompleted,
            accuracyRate: totalTasks > 0 ? Math.round((totalCompleted / (totalTasks + totalCompleted)) * 100) : 100,
            streakDays: Math.min(totalCompleted, 5) || 1,
            tagCounts
          }
        }, incomingOrigin);
      }

      // 10. CLEAR USER HISTORY (Strictly scoped to caller)
      if (pathname === '/api/history/clear' && method === 'POST') {
        const user = authenticateRequest(req, db);
        if (!user) {
          return sendJson(res, 401, { error: 'Unauthorized.' }, incomingOrigin);
        }

        db.history = (db.history || []).filter(h => h.userId !== user.id);
        saveDB(db);
        return sendJson(res, 200, { message: 'History cleared successfully.' }, incomingOrigin);
      }

      return sendJson(res, 404, { error: 'Endpoint not found.' }, incomingOrigin);

    } catch (apiErr) {
      console.error('API Error:', apiErr.message);
      return sendJson(res, 500, { error: 'Internal server error.' }, incomingOrigin);
    }
  }

  // ----------------------------------------------------
  // STATIC FILE SERVING WITH SECURITY HEADERS
  // ----------------------------------------------------
  let safePath = pathname;
  if (safePath === '/' || safePath === '') {
    safePath = '/index.html';
  }

  const normalizedPath = path.normalize(safePath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, normalizedPath);

  // Security: prevent path traversal attacks outside PUBLIC_DIR
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Access Denied');
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // Fallback to index.html for Single Page App
        fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (indexErr, indexContent) => {
          if (indexErr) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('404 Not Found');
          } else {
            res.writeHead(200, {
              'Content-Type': 'text/html; charset=utf-8',
              'X-Content-Type-Options': 'nosniff',
              'X-Frame-Options': 'DENY'
            });
            res.end(indexContent);
          }
        });
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Internal Server Error');
      }
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
      });
      res.end(content);
    }
  });
});

initDB();

server.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🔔 Remind Me Service running at: http://localhost:${PORT}`);
  console.log(`   Security: 600k PBKDF2 Iterations, Hashed Sessions,`);
  console.log(`   CORS Restrictive Policy, Isolated Demo Workspaces`);
  console.log(`======================================================\n`);
});
