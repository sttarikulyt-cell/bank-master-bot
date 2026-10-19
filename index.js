const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');
const TelegramBot = require('node-telegram-bot-api');

// ================= কনফিগ =================
const BOT_TOKEN = process.env.BOT_TOKEN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const SETUP_KEY = process.env.SETUP_KEY;
const API_URL = process.env.API_URL || '';
const WEB_APP_URL = process.env.WEB_APP_URL || 'https://bank-master-bot.web.app';
const BOT_USERNAME = process.env.BOT_USERNAME || 'Bank_MasterBot';
const ADMIN_IDS = (process.env.ADMIN_TELEGRAM_IDS || '').split(',').map(s => s.trim()).filter(Boolean);

if (!BOT_TOKEN || !WEBHOOK_SECRET || !process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error('BOT_TOKEN, WEBHOOK_SECRET ও FIREBASE_SERVICE_ACCOUNT_JSON এনভায়রনমেন্ট ভেরিয়েবল সেট করুন');
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),
  });
}
const db = admin.firestore();
const FV = admin.firestore.FieldValue;
const bot = new TelegramBot(BOT_TOKEN, { polling: false });

const EARNED_TYPES = new Set(['task_reward', 'ad_reward', 'referral_bonus', 'daily_login_bonus', 'admin_adjustment']);

const DEFAULT_SETTINGS = {
  notice: 'স্বাগতম Bank Master-এ! প্রতিদিন লগইন করুন, বোনাস নিন।',
  dailyLoginBonus: 10,
  streakStep: 1,      // প্রতিদিন স্ট্রিকে কত টাকা বাড়বে
  streakCap: 6,       // সর্বোচ্চ কত দিন পর্যন্ত বাড়বে
  referralBonus: 20,
  minReferralsForWithdrawal: 0,
  adNetworks: {
    monetag: { name: 'Monetag', active: false, reward: 1, dailyLimit: 10, timerSeconds: 15, zoneId: '' },
    adexora: { name: 'Adexora', active: false, reward: 1, dailyLimit: 10, timerSeconds: 15, zoneId: '' },
    adsgram: { name: 'Adsgram', active: false, reward: 1, dailyLimit: 10, timerSeconds: 15, zoneId: '' },
    richads: { name: 'RichAds', active: false, reward: 1, dailyLimit: 10, timerSeconds: 15, zoneId: '' },
    gigapub: { name: 'GigaPub', active: false, reward: 1, dailyLimit: 10, timerSeconds: 15, zoneId: '' },
  },
  paymentMethods: {
    bkash: { name: 'bKash', active: true, minWithdrawal: 100 },
    nagad: { name: 'Nagad', active: true, minWithdrawal: 100 },
    rocket: { name: 'Rocket', active: true, minWithdrawal: 100 },
  },
};

// ================= হেল্পার =================
const dhakaDate = (d = new Date()) => d.toLocaleDateString('en-CA', { timeZone: 'Asia/Dhaka' });
const httpError = (status, message) => Object.assign(new Error(message), { status });
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const num = (v, min = 0) => {
  const n = Number(v);
  if (!Number.isFinite(n) || n < min) throw httpError(400, 'সংখ্যা সঠিক নয়');
  return n;
};
const serialize = d => {
  const o = { id: d.id, ...d.data() };
  for (const k in o) if (o[k] && typeof o[k].toMillis === 'function') o[k] = o[k].toMillis();
  return o;
};

async function getSettings() {
  const snap = await db.collection('settings').doc('config').get();
  const data = snap.exists ? snap.data() : {};
  return {
    ...DEFAULT_SETTINGS,
    ...data,
    adNetworks: { ...DEFAULT_SETTINGS.adNetworks, ...(data.adNetworks || {}) },
    paymentMethods: { ...DEFAULT_SETTINGS.paymentMethods, ...(data.paymentMethods || {}) },
  };
}

// Telegram WebApp initData যাচাই (নকল রিকোয়েস্ট ঠেকাতে)
function verifyInitData(initData) {
  if (!initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dataCheck = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const calc = crypto.createHmac('sha256', secret).update(dataCheck).digest('hex');
  if (calc.length !== hash.length || !crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hash))) return null;
  const authDate = Number(params.get('auth_date'));
  if (!authDate || Date.now() / 1000 - authDate > 86400) return null;
  try { return JSON.parse(params.get('user')); } catch { return null; }
}

function userAuth(req, res, next) {
  const tg = verifyInitData(req.get('x-init-data'));
  if (!tg) return next(httpError(401, 'Telegram সেশন যাচাই করা যায়নি। অ্যাপটি Telegram বট থেকে খুলুন।'));
  req.tg = tg;
  req.uid = String(tg.id);
  next();
}

async function adminAuth(req, res, next) {
  try {
    const token = (req.get('authorization') || '').replace('Bearer ', '');
    if (!token) throw httpError(401, 'লগইন প্রয়োজন');
    const decoded = await admin.auth().verifyIdToken(token);
    const adm = await db.collection('admins').doc(decoded.uid).get();
    if (!adm.exists) throw httpError(403, 'আপনি অ্যাডমিন নন');
    req.adminUid = decoded.uid;
    next();
  } catch (e) {
    next(e.status ? e : httpError(401, 'সেশন বৈধ নয়'));
  }
}

async function ensureUser(tg, refParam) {
  const ref = db.collection('users').doc(String(tg.id));
  return db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (snap.exists) return snap.data();
    let referredBy = null;
    if (refParam && /^ref_\d+$/.test(refParam)) {
      const r = refParam.slice(4);
      if (r !== String(tg.id)) referredBy = r;
    }
    const data = {
      userId: String(tg.id),
      userName: tg.username || tg.first_name || `user_${tg.id}`,
      firstName: tg.first_name || '',
      balance: 0,
      totalEarned: 0,
      totalWithdrawn: 0,
      referredBy,
      referralRewarded: false,
      referralCount: 0,
      loginStreak: 0,
      lastBonusDate: null,
    };
    tx.set(ref, { ...data, createdAt: FV.serverTimestamp() });
    return data;
  });
}

// একই ট্রানজেকশনের ভিতরে ব্যালেন্স বাড়ানো/কমানো (সব রিড আগে হতে হবে)
function creditTx(tx, uid, cur, amount, type, relatedId = null, extra = {}) {
  const balance = (cur.balance || 0) + amount;
  const upd = { ...extra, balance };
  if (EARNED_TYPES.has(type) && amount > 0) upd.totalEarned = (cur.totalEarned || 0) + amount;
  tx.update(db.collection('users').doc(uid), upd);
  tx.set(db.collection('walletTransactions').doc(), {
    userId: uid, amount, type, relatedId, createdAt: FV.serverTimestamp(),
  });
  return balance;
}

// রেফারার বোনাস: রেফারড ইউজারের প্রথম সফল টাস্কের পর, একবারই
async function rewardReferrerIfNeeded(uid) {
  const settings = await getSettings();
  const uref = db.collection('users').doc(uid);
  await db.runTransaction(async tx => {
    const me = (await tx.get(uref)).data();
    if (!me || !me.referredBy || me.referralRewarded) return;
    const rref = db.collection('users').doc(me.referredBy);
    const r = await tx.get(rref);
    tx.update(uref, { referralRewarded: true });
    if (!r.exists) return;
    creditTx(tx, me.referredBy, r.data(), settings.referralBonus, 'referral_bonus', uid, {
      referralCount: FV.increment(1),
    });
  });
}

// ================= ইউজার API =================
app.get('/api/me', userAuth, wrap(async (req, res) => {
  const user = await ensureUser(req.tg, req.query.start);
  const uid = req.uid;
  const [s, tasksSnap, compSnap, startSnap, wdSnap] = await Promise.all([
    getSettings(),
    db.collection('tasks').where('active', '==', true).get(),
    db.collection('taskCompletions').where('userId', '==', uid).get(),
    db.collection('taskStarts').where('userId', '==', uid).get(),
    db.collection('withdrawals').where('userId', '==', uid).get(),
  ]);

  const now = Date.now();
  const comp = {};
  compSnap.docs.forEach(d => { comp[d.data().taskId] = d.data(); });
  const starts = {};
  startSnap.docs.forEach(d => { starts[d.data().taskId] = d.data().startedAt; });

  const tasks = tasksSnap.docs.map(d => {
    const t = d.data();
    const c = comp[d.id];
    let status = 'available';
    let availableAt = 0;
    if (c && !t.recurring) status = 'done';
    if (c && t.recurring) {
      availableAt = c.lastCompletedAt + (t.resetIntervalSeconds || 0) * 1000;
      if (now < availableAt) status = 'cooldown';
    }
    return {
      id: d.id,
      title: t.title,
      description: t.description || '',
      url: t.url || '',
      reward: t.reward,
      durationSeconds: t.durationSeconds || 0,
      requiresCode: !!t.requiredCode,
      status,
      availableAt,
      startedAt: starts[d.id] || 0,
    };
  });

  const withdrawals = wdSnap.docs
    .map(serialize)
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
    .slice(0, 10)
    .map(w => ({
      id: w.id, amount: w.amount, method: w.method, account: w.account,
      status: w.status, rejectionReason: w.rejectionReason || '', createdAt: w.createdAt || 0,
    }));

  res.json({
    success: true,
    user: {
      userId: user.userId,
      firstName: user.firstName || '',
      balance: user.balance || 0,
      totalEarned: user.totalEarned || 0,
      totalWithdrawn: user.totalWithdrawn || 0,
      loginStreak: user.loginStreak || 0,
      referralCount: user.referralCount || 0,
    },
    bonusClaimedToday: user.lastBonusDate === dhakaDate(),
    notice: s.notice,
    referralBonus: s.referralBonus,
    minReferralsForWithdrawal: s.minReferralsForWithdrawal,
    referralLink: `https://t.me/${BOT_USERNAME}?start=ref_${uid}`,
    tasks,
    ads: Object.entries(s.adNetworks)
      .filter(([, n]) => n.active)
      .map(([code, n]) => ({ code, name: n.name, reward: n.reward, dailyLimit: n.dailyLimit, timerSeconds: n.timerSeconds })),
    paymentMethods: Object.entries(s.paymentMethods)
      .filter(([, m]) => m.active)
      .map(([code, m]) => ({ code, name: m.name, minWithdrawal: m.minWithdrawal })),
    withdrawals,
  });
}));

app.post('/api/daily-bonus', userAuth, wrap(async (req, res) => {
  const s = await getSettings();
  const today = dhakaDate();
  const yesterday = dhakaDate(new Date(Date.now() - 86400000));
  const userRef = db.collection('users').doc(req.uid);

  const out = await db.runTransaction(async tx => {
    const snap = await tx.get(userRef);
    if (!snap.exists) throw httpError(404, 'ইউজার পাওয়া যায়নি');
    const u = snap.data();
    if (u.lastBonusDate === today) {
      return { claimed: false, streak: u.loginStreak || 0, balance: u.balance || 0 };
    }
    const streak = u.lastBonusDate === yesterday ? (u.loginStreak || 0) + 1 : 1;
    const bonus = s.dailyLoginBonus + Math.min(streak - 1, s.streakCap) * s.streakStep;
    const balance = creditTx(tx, req.uid, u, bonus, 'daily_login_bonus', today, {
      lastBonusDate: today,
      loginStreak: streak,
    });
    return { claimed: true, bonus, streak, balance };
  });
  res.json({ success: true, ...out });
}));

app.post('/api/tasks/start', userAuth, wrap(async (req, res) => {
  const taskId = String(req.body.taskId || '');
  const taskSnap = await db.collection('tasks').doc(taskId).get();
  if (!taskSnap.exists || !taskSnap.data().active) throw httpError(404, 'টাস্ক পাওয়া যায়নি');
  const t = taskSnap.data();
  const key = `${req.uid}_${taskId}`;

  const doneSnap = await db.collection('taskCompletions').doc(key).get();
  if (doneSnap.exists && !t.recurring) throw httpError(409, 'এই টাস্ক ইতিমধ্যে সম্পন্ন');
  if (doneSnap.exists && t.recurring) {
    const next = doneSnap.data().lastCompletedAt + (t.resetIntervalSeconds || 0) * 1000;
    if (Date.now() < next) throw httpError(425, 'টাস্কটি এখনো রিসেট হয়নি');
  }

  const sRef = db.collection('taskStarts').doc(key);
  const sSnap = await sRef.get();
  // আগের শুরুর সময় থাকলে সেটাই ধরা হবে (টাইমার রিসেট করে ঠকানো যাবে না)
  const startedAt = sSnap.exists ? sSnap.data().startedAt : Date.now();
  if (!sSnap.exists) await sRef.set({ userId: req.uid, taskId, startedAt });
  res.json({ success: true, startedAt, durationSeconds: t.durationSeconds || 0 });
}));

app.post('/api/tasks/complete', userAuth, wrap(async (req, res) => {
  const taskId = String(req.body.taskId || '');
  const code = String(req.body.code || '').trim();
  const key = `${req.uid}_${taskId}`;
  const taskRef = db.collection('tasks').doc(taskId);
  const compRef = db.collection('taskCompletions').doc(key);
  const startRef = db.collection('taskStarts').doc(key);
  const userRef = db.collection('users').doc(req.uid);
  const now = Date.now();

  const result = await db.runTransaction(async tx => {
    const [tSnap, cSnap, sSnap, uSnap] = await Promise.all([
      tx.get(taskRef), tx.get(compRef), tx.get(startRef), tx.get(userRef),
    ]);
    if (!tSnap.exists || !tSnap.data().active) throw httpError(404, 'টাস্ক পাওয়া যায়নি');
    if (!uSnap.exists) throw httpError(404, 'ইউজার পাওয়া যায়নি');
    const t = tSnap.data();

    if (t.requiredCode && code !== t.requiredCode) throw httpError(400, 'কোডটি সঠিক নয়');
    if (cSnap.exists && !t.recurring) throw httpError(409, 'এই টাস্ক ইতিমধ্যে সম্পন্ন');
    if (cSnap.exists && t.recurring) {
      const next = cSnap.data().lastCompletedAt + (t.resetIntervalSeconds || 0) * 1000;
      if (now < next) throw httpError(425, `আবার ${Math.ceil((next - now) / 60000)} মিনিট পর`);
    }
    const dur = (t.durationSeconds || 0) * 1000;
    if (dur > 0) {
      if (!sSnap.exists) throw httpError(425, 'আগে টাস্ক শুরু করুন');
      const wait = sSnap.data().startedAt + dur - now;
      if (wait > 0) throw httpError(425, `আরও ${Math.ceil(wait / 1000)} সেকেন্ড অপেক্ষা করুন`);
    }

    const balance = creditTx(tx, req.uid, uSnap.data(), t.reward, 'task_reward', taskId);
    tx.set(compRef, { userId: req.uid, taskId, lastCompletedAt: now, count: FV.increment(1) }, { merge: true });
    tx.delete(startRef);
    return { balance, reward: t.reward };
  });

  await rewardReferrerIfNeeded(req.uid);
  res.json({ success: true, ...result });
}));

app.post('/api/ad/start', userAuth, wrap(async (req, res) => {
  const network = String(req.body.network || '');
  const s = await getSettings();
  const net = s.adNetworks[network];
  if (!net || !net.active) throw httpError(400, 'এই অ্যাড নেটওয়ার্ক চালু নেই');

  const today = dhakaDate();
  const daily = await db.collection('adDaily').doc(`${req.uid}_${network}_${today}`).get();
  const count = daily.exists ? daily.data().count : 0;
  if (count >= net.dailyLimit) throw httpError(429, 'আজকের লিমিট শেষ');

  await db.collection('adSessions').doc(req.uid).set({ network, startedAt: Date.now() });
  res.json({ success: true, timerSeconds: net.timerSeconds, zoneId: net.zoneId, remaining: net.dailyLimit - count });
}));

app.post('/api/ad/claim', userAuth, wrap(async (req, res) => {
  const network = String(req.body.network || '');
  const s = await getSettings();
  const net = s.adNetworks[network];
  if (!net || !net.active) throw httpError(400, 'এই অ্যাড নেটওয়ার্ক চালু নেই');

  const today = dhakaDate();
  const sessRef = db.collection('adSessions').doc(req.uid);
  const dailyRef = db.collection('adDaily').doc(`${req.uid}_${network}_${today}`);
  const userRef = db.collection('users').doc(req.uid);

  const balance = await db.runTransaction(async tx => {
    const [sess, daily, user] = await Promise.all([tx.get(sessRef), tx.get(dailyRef), tx.get(userRef)]);
    if (!sess.exists || sess.data().network !== network) throw httpError(400, 'আগে অ্যাড শুরু করুন');
    if (Date.now() - sess.data().startedAt < net.timerSeconds * 1000 - 1000) {
      throw httpError(425, 'অ্যাড সম্পূর্ণ দেখা হয়নি');
    }
    if (!user.exists) throw httpError(404, 'ইউজার পাওয়া যায়নি');
    const count = daily.exists ? daily.data().count : 0;
    if (count >= net.dailyLimit) throw httpError(429, 'আজকের লিমিট শেষ');

    tx.delete(sessRef);
    tx.set(dailyRef, { count: count + 1, userId: req.uid, network, date: today }, { merge: true });
    return creditTx(tx, req.uid, user.data(), net.reward, 'ad_reward', network);
  });
  res.json({ success: true, reward: net.reward, balance });
}));

app.post('/api/withdraw', userAuth, wrap(async (req, res) => {
  const method = String(req.body.method || '');
  const account = String(req.body.account || '').replace(/[\s-]/g, '');
  const amount = Math.floor(Number(req.body.amount));
  const s = await getSettings();

  const pm = s.paymentMethods[method];
  if (!pm || !pm.active) throw httpError(400, 'এই পেমেন্ট মেথড চালু নেই');
  if (!/^01[3-9]\d{8}$/.test(account)) throw httpError(400, 'সঠিক ১১ সংখ্যার মোবাইল নম্বর দিন');
  if (!Number.isFinite(amount) || amount < pm.minWithdrawal) {
    throw httpError(400, `সর্বনিম্ন উইথড্র ${pm.minWithdrawal} টাকা`);
  }

  const pending = await db.collection('withdrawals')
    .where('userId', '==', req.uid).where('status', '==', 'pending').limit(1).get();
  if (!pending.empty) throw httpError(409, 'আপনার একটি উইথড্র অপেক্ষমাণ আছে');

  const userRef = db.collection('users').doc(req.uid);
  const result = await db.runTransaction(async tx => {
    const snap = await tx.get(userRef);
    if (!snap.exists) throw httpError(404, 'ইউজার পাওয়া যায়নি');
    const u = snap.data();
    if ((u.referralCount || 0) < s.minReferralsForWithdrawal) {
      throw httpError(400, `উইথড্রের জন্য ${s.minReferralsForWithdrawal} জন রেফারেল লাগবে`);
    }
    if ((u.balance || 0) < amount) throw httpError(400, 'পর্যাপ্ত ব্যালেন্স নেই');

    const wref = db.collection('withdrawals').doc();
    tx.set(wref, {
      userId: req.uid, userName: u.userName, method, account, amount,
      status: 'pending', rejectionReason: null, createdAt: FV.serverTimestamp(),
    });
    const balance = creditTx(tx, req.uid, u, -amount, 'withdrawal_request', wref.id);
    return { id: wref.id, balance };
  });
  res.json({ success: true, ...result });
}));


// ================= অ্যাডমিন API =================
function cleanTask(d = {}) {
  const title = String(d.title || '').trim().slice(0, 120);
  const reward = Number(d.reward);
  if (!title) throw httpError(400, 'শিরোনাম দিন');
  if (!(reward > 0)) throw httpError(400, 'পুরস্কার সঠিক নয়');
  return {
    title,
    description: String(d.description || '').slice(0, 500),
    url: String(d.url || '').slice(0, 500),
    reward,
    durationSeconds: Math.max(0, Math.floor(Number(d.durationSeconds) || 0)),
    recurring: !!d.recurring,
    resetIntervalSeconds: Math.max(0, Math.floor(Number(d.resetIntervalSeconds) || 0)),
    requiredCode: String(d.requiredCode || '').trim().slice(0, 100),
  };
}

function sanitizeNetworks(input = {}) {
  const out = {};
  for (const code of Object.keys(DEFAULT_SETTINGS.adNetworks)) {
    const n = input[code];
    if (!n) continue;
    out[code] = {
      name: DEFAULT_SETTINGS.adNetworks[code].name,
      active: !!n.active,
      reward: num(n.reward),
      dailyLimit: Math.floor(num(n.dailyLimit)),
      timerSeconds: Math.floor(num(n.timerSeconds)),
      zoneId: String(n.zoneId || '').slice(0, 100),
    };
  }
  return out;
}

function sanitizeMethods(input = {}) {
  const out = {};
  for (const code of Object.keys(DEFAULT_SETTINGS.paymentMethods)) {
    const m = input[code];
    if (!m) continue;
    out[code] = {
      name: DEFAULT_SETTINGS.paymentMethods[code].name,
      active: !!m.active,
      minWithdrawal: num(m.minWithdrawal),
    };
  }
  return out;
}

app.get('/api/admin/overview', adminAuth, wrap(async (req, res) => {
  const [settings, tasks, wds, usersCount, top] = await Promise.all([
    getSettings(),
    db.collection('tasks').get(),
    db.collection('withdrawals').orderBy('createdAt', 'desc').limit(200).get(),
    db.collection('users').count().get(),
    db.collection('users').orderBy('balance', 'desc').limit(20).get(),
  ]);
  const withdrawals = wds.docs.map(serialize);
  const pending = withdrawals.filter(w => w.status === 'pending');
  res.json({
    success: true,
    settings,
    tasks: tasks.docs.map(serialize),
    withdrawals,
    topUsers: top.docs.map(serialize),
    stats: {
      users: usersCount.data().count,
      pendingWithdrawals: pending.length,
      pendingAmount: pending.reduce((a, w) => a + (w.amount || 0), 0),
    },
  });
}));

app.post('/api/admin/task', adminAuth, wrap(async (req, res) => {
  const { action, id, data } = req.body || {};
  const col = db.collection('tasks');
  if (action === 'create') {
    await col.add({ ...cleanTask(data), active: true, createdAt: FV.serverTimestamp() });
  } else if (action === 'update') {
    await col.doc(String(id)).update(cleanTask(data));
  } else if (action === 'toggle') {
    const d = await col.doc(String(id)).get();
    if (!d.exists) throw httpError(404, 'টাস্ক নেই');
    await col.doc(String(id)).update({ active: !d.data().active });
  } else if (action === 'delete') {
    await col.doc(String(id)).delete();
  } else {
    throw httpError(400, 'ভুল অ্যাকশন');
  }
  res.json({ success: true });
}));

app.post('/api/admin/withdrawal', adminAuth, wrap(async (req, res) => {
  const { id, action, reason } = req.body || {};
  const wref = db.collection('withdrawals').doc(String(id));
  await db.runTransaction(async tx => {
    const w = await tx.get(wref);
    if (!w.exists) throw httpError(404, 'উইথড্র পাওয়া যায়নি');
    const d = w.data();
    if (d.status !== 'pending') throw httpError(409, 'ইতিমধ্যে প্রক্রিয়া হয়েছে');
    const uref = db.collection('users').doc(d.userId);

    if (action === 'approve') {
      tx.update(wref, { status: 'approved', processedAt: FV.serverTimestamp(), processedBy: req.adminUid });
      tx.update(uref, { totalWithdrawn: FV.increment(d.amount) });
    } else if (action === 'reject') {
      const u = await tx.get(uref);
      tx.update(wref, {
        status: 'rejected',
        rejectionReason: String(reason || '').slice(0, 200),
        processedAt: FV.serverTimestamp(),
        processedBy: req.adminUid,
      });
      if (u.exists) creditTx(tx, d.userId, u.data(), d.amount, 'withdrawal_refund', String(id));
    } else {
      throw httpError(400, 'ভুল অ্যাকশন');
    }
  });
  res.json({ success: true });
}));

app.post('/api/admin/settings', adminAuth, wrap(async (req, res) => {
  const d = req.body || {};
  const patch = {};
  if (d.notice !== undefined) patch.notice = String(d.notice).slice(0, 300);
  if (d.dailyLoginBonus !== undefined) patch.dailyLoginBonus = num(d.dailyLoginBonus);
  if (d.streakStep !== undefined) patch.streakStep = num(d.streakStep);
  if (d.streakCap !== undefined) patch.streakCap = Math.floor(num(d.streakCap));
  if (d.referralBonus !== undefined) patch.referralBonus = num(d.referralBonus);
  if (d.minReferralsForWithdrawal !== undefined) patch.minReferralsForWithdrawal = Math.floor(num(d.minReferralsForWithdrawal));
  if (d.adNetworks) patch.adNetworks = sanitizeNetworks(d.adNetworks);
  if (d.paymentMethods) patch.paymentMethods = sanitizeMethods(d.paymentMethods);
  await db.collection('settings').doc('config').set(patch, { merge: true });
  res.json({ success: true });
}));

app.post('/api/admin/adjust', adminAuth, wrap(async (req, res) => {
  const uid = String(req.body.userId || '').trim();
  const amount = Number(req.body.amount);
  if (!uid || !Number.isFinite(amount) || amount === 0) throw httpError(400, 'তথ্য সঠিক নয়');
  const ref = db.collection('users').doc(uid);
  const balance = await db.runTransaction(async tx => {
    const u = await tx.get(ref);
    if (!u.exists) throw httpError(404, 'ইউজার নেই');
    if ((u.data().balance || 0) + amount < 0) throw httpError(400, 'ব্যালেন্স ঋণাত্মক হবে না');
    return creditTx(tx, uid, u.data(), amount, 'admin_adjustment', String(req.body.reason || '').slice(0, 200));
  });
  res.json({ success: true, balance });
}));

// ================= বট (Webhook) =================
function welcomeText(from) {
  return `🎉 স্বাগতম ${from.first_name || ''}!\n\n` +
    `Bank Master-এ আয় শুরু করতে নিচের বাটনে চাপুন।\n\n` +
    `✅ প্রতিদিন লগইন করে বোনাস নিন\n` +
    `✅ টাস্ক সম্পন্ন করে টাকা জিতুন\n` +
    `✅ বন্ধুকে রেফার করে বোনাস পান`;
}

async function handleMessage(msg) {
  if (!msg || !msg.text || !msg.from) return;
  const text = msg.text.trim();
  const chatId = msg.chat.id;

  if (text.startsWith('/start')) {
    const param = text.split(/\s+/)[1];
    await ensureUser(msg.from, param);
    return bot.sendMessage(chatId, welcomeText(msg.from), {
      reply_markup: { inline_keyboard: [[{ text: '🚀 অ্যাপ খুলুন', web_app: { url: WEB_APP_URL } }]] },
    });
  }
  if (text.startsWith('/balance')) {
    const u = await ensureUser(msg.from);
    return bot.sendMessage(chatId, `💰 বর্তমান ব্যালেন্স: ${u.balance} ৳\n📈 মোট অর্জিত: ${u.totalEarned} ৳`);
  }
  if (text.startsWith('/stats')) {
    if (!ADMIN_IDS.includes(String(msg.from.id))) return bot.sendMessage(chatId, '⛔ শুধু অ্যাডমিন দেখতে পারবেন');
    const users = await db.collection('users').count().get();
    const pend = await db.collection('withdrawals').where('status', '==', 'pending').count().get();
    return bot.sendMessage(chatId, `👥 মোট ইউজার: ${users.data().count}\n⏳ পেন্ডিং উইথড্র: ${pend.data().count}`);
  }
}

app.post('/tg', wrap(async (req, res) => {
  if (req.get('x-telegram-bot-api-secret-token') !== WEBHOOK_SECRET) return res.sendStatus(403);
  try {
    await handleMessage(req.body.message);
  } catch (e) {
    console.error('bot error:', e.message);
  }
  res.sendStatus(200);
}));

app.get('/setup-webhook', wrap(async (req, res) => {
  if (!SETUP_KEY || req.query.key !== SETUP_KEY) return res.sendStatus(403);
  await bot.setWebHook(`${API_URL}/tg`, { secret_token: WEBHOOK_SECRET });
  res.json({ success: true, message: 'Webhook সেট হয়েছে' });
}));

app.get('/', (req, res) => res.json({ ok: true, message: 'Bank Master API চলছে' }));

app.use((err, req, res, next) => {
  if (err.status) return res.status(err.status).json({ success: false, message: err.message });
  console.error(err);
  res.status(500).json({ success: false, message: 'সার্ভারে সমস্যা হয়েছে' });
});

module.exports = app;

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => console.log('Local server চালু'));
}
