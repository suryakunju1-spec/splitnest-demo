'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const SESSION_COOKIE = 'splitnest_session';
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_JSON_BODY_BYTES = 16 * 1024;

const DUMMY_SALT = crypto.randomBytes(16).toString('hex');
const DUMMY_HASH = crypto.scryptSync('dummy-password-placeholder', DUMMY_SALT, 64);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const PUBLIC_HTML_FILES = new Set([
  '/index.html',
  '/dashboard.html',
  '/signup.html',
  '/login.html',
  '/activity.html',
]);

const PUBLIC_ASSET_PREFIXES = ['/css/', '/js/', '/img/', '/data/'];

function normalizeFlat(value) {
  if (typeof value !== 'string') return '';
  return value
    .trim()
    .replace(/^(?:flat|apt|apartment|unit|#)\s*/i, '')
    .trim()
    .toUpperCase();
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function isValidEmail(email) {
  return email.length > 0 && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidFlat(flat) {
  return /^[A-Z0-9-]{1,16}$/.test(flat);
}

function parseCookies(cookieHeader) {
  const out = Object.create(null);
  if (typeof cookieHeader !== 'string' || !cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const rawVal = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(rawVal);
    } catch (_) {
      out[key] = rawVal;
    }
  }
  return out;
}

function isSecureRequest(req) {
  if (req.socket && req.socket.encrypted) return true;
  const proto = req.headers['x-forwarded-proto'];
  if (typeof proto === 'string') {
    return proto.split(',')[0].trim().toLowerCase() === 'https';
  }
  return false;
}

function formatSessionCookie(token, maxAgeSeconds, secure) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function verifyPassword(password, user) {
  if (!user || typeof password !== 'string') {
    const candidate = crypto.scryptSync(String(password || ''), DUMMY_SALT, 64);
    crypto.timingSafeEqual(candidate, DUMMY_HASH);
    return false;
  }
  const candidate = crypto.scryptSync(password, user.salt, 64);
  const expected = Buffer.from(user.passwordHash, 'hex');
  if (candidate.length !== expected.length) return false;
  return crypto.timingSafeEqual(candidate, expected);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('application/json')) {
      const err = new Error('Content-Type must be application/json');
      err.statusCode = 415;
      reject(err);
      return;
    }

    const chunks = [];
    let total = 0;
    let aborted = false;

    req.on('data', chunk => {
      if (aborted) return;
      total += chunk.length;
      if (total > MAX_JSON_BODY_BYTES) {
        aborted = true;
        const err = new Error('Request payload too large');
        err.statusCode = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        const parsed = raw ? JSON.parse(raw) : {};
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          const err = new Error('Expected JSON object');
          err.statusCode = 400;
          reject(err);
          return;
        }
        resolve(parsed);
      } catch (_) {
        const err = new Error('Invalid JSON payload');
        err.statusCode = 400;
        reject(err);
      }
    });

    req.on('error', err => {
      if (!aborted) reject(err);
    });
  });
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(body);
}

function sendText(res, statusCode, message, method = 'GET') {
  const body = Buffer.from(message, 'utf8');
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': body.length,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(method === 'HEAD' ? undefined : body);
}

function isAllowedPublicPath(pathname) {
  if (!pathname || pathname.includes('\0') || pathname.includes('\\')) return false;
  if (PUBLIC_HTML_FILES.has(pathname)) return true;
  if (!PUBLIC_ASSET_PREFIXES.some(prefix => pathname.startsWith(prefix))) return false;
  const segments = pathname.split('/').filter(Boolean);
  if (segments.some(seg => seg === '.' || seg === '..' || seg.startsWith('.'))) return false;
  return true;
}

function createApp(options = {}) {
  const rootDir = path.resolve(options.rootDir || __dirname);
  const privateDir = path.resolve(options.privateDir || path.join(rootDir, 'server', 'private'));
  const sessionTtlMs = Number(options.sessionTtlMs || process.env.SESSION_TTL_MS || DEFAULT_SESSION_TTL_MS);
  const nowFn = typeof options.now === 'function' ? options.now : () => Date.now();

  const rawHouseholds = JSON.parse(
    fs.readFileSync(path.join(privateDir, 'households.json'), 'utf8')
  );
  const householdsByFlat = new Map();
  for (const h of rawHouseholds) {
    const flat = normalizeFlat(h.flat);
    householdsByFlat.set(flat, {
      flat,
      neighborhood: h.neighborhood || '',
      payments: Array.isArray(h.payments) ? h.payments.map(p => ({ ...p })) : [],
    });
  }

  const usersByEmail = new Map();
  const usersFile = path.join(privateDir, 'users.json');
  if (fs.existsSync(usersFile)) {
    const rawUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    for (const u of rawUsers) {
      const email = normalizeEmail(u.email);
      const flat = normalizeFlat(u.flat);
      if (email && flat && u.salt && u.passwordHash) {
        usersByEmail.set(email, {
          email,
          name: u.name || '',
          flat,
          salt: u.salt,
          passwordHash: u.passwordHash,
          seeded: Boolean(u.seeded),
        });
      }
    }
  }

  const sessions = new Map();

  function getValidSession(req) {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (!token) return { session: null, hadCookie: false };
    const session = sessions.get(token);
    if (!session) return { session: null, hadCookie: true };
    if (nowFn() >= session.expiresAt) {
      sessions.delete(token);
      return { session: null, hadCookie: true };
    }
    return { session, hadCookie: true };
  }

  function issueSession(req, res, { email, flat }) {
    const existingCookies = parseCookies(req.headers.cookie);
    if (existingCookies[SESSION_COOKIE]) {
      sessions.delete(existingCookies[SESSION_COOKIE]);
    }
    const token = crypto.randomBytes(32).toString('hex');
    const createdAt = nowFn();
    sessions.set(token, {
      email,
      flat,
      createdAt,
      expiresAt: createdAt + sessionTtlMs,
    });
    const maxAgeSec = Math.max(1, Math.ceil(sessionTtlMs / 1000));
    return formatSessionCookie(token, maxAgeSec, isSecureRequest(req));
  }

  async function handleApi(req, res, reqUrl) {
    const pathname = reqUrl.pathname;

    if (pathname === '/api/signup') {
      if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
      }
      let body;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        return sendJson(res, err.statusCode || 400, { error: err.message });
      }

      const email = normalizeEmail(body.email);
      const password = body.password;
      const rawUnit = typeof body.unit === 'string' && body.unit.trim() ? body.unit : body.flat;
      const flat = normalizeFlat(rawUnit);

      if (
        !isValidEmail(email) ||
        typeof password !== 'string' ||
        password.length < 8 ||
        password.length > 256 ||
        !isValidFlat(flat)
      ) {
        return sendJson(res, 400, {
          error: 'Valid email, password, and apartment/unit are required.',
        });
      }

      const existing = usersByEmail.get(email);
      if (existing && (!existing.seeded || existing.flat !== flat)) {
        return sendJson(res, 409, { error: 'An account with this email already exists.' });
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = crypto.scryptSync(password, salt, 64).toString('hex');
      const firstName = typeof body.firstName === 'string' ? body.firstName.trim().slice(0, 80) : '';
      const lastName = typeof body.lastName === 'string' ? body.lastName.trim().slice(0, 80) : '';
      const fullName = [firstName, lastName].filter(Boolean).join(' ') || (existing ? existing.name : '');

      usersByEmail.set(email, {
        email,
        name: fullName,
        flat,
        salt,
        passwordHash,
        seeded: false,
      });

      if (!householdsByFlat.has(flat)) {
        householdsByFlat.set(flat, {
          flat,
          neighborhood: '',
          payments: [],
        });
      }

      const setCookie = issueSession(req, res, { email, flat });
      return sendJson(res, 201, { email, flat }, { 'Set-Cookie': setCookie });
    }

    if (pathname === '/api/login') {
      if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
      }
      let body;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        return sendJson(res, err.statusCode || 400, { error: err.message });
      }

      const email = normalizeEmail(body.email);
      const password = typeof body.password === 'string' ? body.password : '';
      const user = isValidEmail(email) ? usersByEmail.get(email) : null;

      if (!verifyPassword(password, user)) {
        return sendJson(res, 401, { error: 'Invalid email or password.' });
      }

      const setCookie = issueSession(req, res, { email: user.email, flat: user.flat });
      return sendJson(res, 200, { email: user.email, flat: user.flat }, { 'Set-Cookie': setCookie });
    }

    if (pathname === '/api/logout') {
      if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
      }
      const cookies = parseCookies(req.headers.cookie);
      if (cookies[SESSION_COOKIE]) {
        sessions.delete(cookies[SESSION_COOKIE]);
      }
      const clearCookie = formatSessionCookie('', 0, isSecureRequest(req));
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearCookie });
    }

    if (pathname === '/api/household') {
      if (req.method !== 'GET') {
        return sendJson(res, 405, { error: 'Method not allowed' }, { Allow: 'GET' });
      }
      const { session, hadCookie } = getValidSession(req);
      if (!session) {
        const extra = hadCookie
          ? { 'Set-Cookie': formatSessionCookie('', 0, isSecureRequest(req)) }
          : {};
        return sendJson(res, 401, { error: 'Authentication required.' }, extra);
      }

      if (reqUrl.searchParams.has('flat')) {
        const requestedFlat = normalizeFlat(reqUrl.searchParams.get('flat'));
        if (!requestedFlat || requestedFlat !== session.flat) {
          return sendJson(res, 403, {
            error: 'Forbidden: you do not have access to the requested household.',
          });
        }
      }

      const household = householdsByFlat.get(session.flat) || {
        flat: session.flat,
        neighborhood: '',
        payments: [],
      };

      return sendJson(res, 200, {
        flat: household.flat,
        neighborhood: household.neighborhood,
        payments: household.payments.map(p => ({
          name: p.name,
          email: p.email,
          amount: p.amount,
          card: p.card,
        })),
      });
    }

    return sendJson(res, 404, { error: 'Not found' });
  }

  function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed');
      return;
    }

    const mappedPath = pathname === '/' ? '/index.html' : pathname;
    if (!isAllowedPublicPath(mappedPath)) {
      return sendText(res, 404, 'Not Found', req.method);
    }

    const absPath = path.resolve(rootDir, '.' + mappedPath);
    if (!absPath.startsWith(rootDir + path.sep)) {
      return sendText(res, 403, 'Forbidden', req.method);
    }

    fs.stat(absPath, (statErr, stats) => {
      if (statErr || !stats.isFile()) {
        return sendText(res, 404, 'Not Found', req.method);
      }
      const ext = path.extname(absPath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Length': stats.size,
        'X-Content-Type-Options': 'nosniff',
      });
      if (req.method === 'HEAD') {
        res.end();
        return;
      }
      const stream = fs.createReadStream(absPath);
      stream.on('error', () => {
        if (!res.headersSent) {
          sendText(res, 500, 'Internal Server Error', req.method);
        } else {
          res.destroy();
        }
      });
      stream.pipe(res);
    });
  }

  const server = http.createServer((req, res) => {
    let reqUrl;
    try {
      reqUrl = new URL(req.url || '/', 'http://localhost');
    } catch (_) {
      return sendText(res, 400, 'Bad Request');
    }

    let decodedPathname;
    try {
      decodedPathname = decodeURIComponent(reqUrl.pathname);
    } catch (_) {
      return sendText(res, 400, 'Bad Request');
    }

    if (decodedPathname === '/api' || decodedPathname.startsWith('/api/')) {
      reqUrl.pathname = decodedPathname;
      handleApi(req, res, reqUrl).catch(() => {
        if (!res.headersSent) {
          sendJson(res, 500, { error: 'Internal server error' });
        } else {
          res.destroy();
        }
      });
      return;
    }

    serveStatic(req, res, decodedPathname);
  });

  return server;
}

function parseCliArgs(argv) {
  let port = Number(process.env.PORT || 3000);
  let host = process.env.HOST || '127.0.0.1';
  for (let i = 0; i < argv.length; i++) {
    if ((argv[i] === '--port' || argv[i] === '-p') && argv[i + 1]) {
      port = Number(argv[++i]);
    } else if (argv[i].startsWith('--port=')) {
      port = Number(argv[i].split('=')[1]);
    } else if ((argv[i] === '--host' || argv[i] === '-H') && argv[i + 1]) {
      host = argv[++i];
    } else if (argv[i].startsWith('--host=')) {
      host = argv[i].split('=')[1];
    }
  }
  return { port, host };
}

if (require.main === module) {
  const { port, host } = parseCliArgs(process.argv.slice(2));
  const server = createApp();
  server.listen(port, host, () => {
    const addr = server.address();
    const boundPort = typeof addr === 'object' && addr ? addr.port : port;
    console.log(`SplitNest server listening on http://${host}:${boundPort}`);
  });
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => {
      server.close(() => process.exit(0));
    });
  }
}

module.exports = { createApp, normalizeFlat };
