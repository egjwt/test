const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 관리자 로그인 유지 2시간
const LOGIN_WINDOW_MS = 15 * 60 * 1000;    // 로그인 시도 제한 구간
const LOGIN_MAX_FAILS = 5;                 // 구간당 허용 실패 횟수
const MAX_NOTICE = 300;
const MAX_TITLE = 100;
const MAX_BODY = 32 * 1024;
const STATS_DAYS = 30;
const MAX_VISITORS_TRACKED = 50000;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const DEFAULT_LINKS = [
  { name: '멜론티켓', url: 'https://ticket.melon.com' },
  { name: 'YES24 티켓', url: 'https://ticket.yes24.com' },
  { name: 'NOL 티켓', url: 'https://tickets.interpark.com' },
  { name: '티켓링크', url: 'https://www.ticketlink.co.kr' },
];
const MAX_LINKS = 12;
const EMPTY_DAY = () => ({ visitors: 0, views: 0, captcha: 0, seat: 0 });

/* ---------- 저장소 (JSON 파일 하나) ---------- */

let state;
function loadState() {
  try {
    state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    state = {};
  }
  delete state.items; // 체크리스트 기능은 없앴음
  state.notice = state.notice || { text: '', on: false };
  state.event = state.event || { title: '', openAt: null };
  delete state.settings;
  if (!Array.isArray(state.links)) state.links = DEFAULT_LINKS.map(l => ({ ...l }));
  state.stats = state.stats || { days: {}, seen: { day: '', ids: [] } };
  saveNow();
}

let saveTimer = null;
function saveNow() {
  clearTimeout(saveTimer); saveTimer = null;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, STATE_FILE);
  } catch (e) {
    console.error('저장 실패:', e.message);
  }
}
// 통계처럼 자주 바뀌는 값은 모아서 저장
function saveSoon() { if (!saveTimer) saveTimer = setTimeout(saveNow, 1000); }
loadState();

/* ---------- 통계 (한국 시간 기준 하루 단위) ---------- */
const dayFmt = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit' });
const today = () => dayFmt.format(new Date());
let seenSet = new Set();
function dayStats(day = today()) {
  const days = state.stats.days;
  if (!days[day]) {
    days[day] = EMPTY_DAY();
    const keys = Object.keys(days).sort();
    while (keys.length > STATS_DAYS) delete days[keys.shift()];
  }
  if (state.stats.seen.day !== day) { state.stats.seen = { day, ids: [] }; seenSet = new Set(); }
  return days[day];
}
seenSet = new Set(state.stats.seen.ids);
function countView(visitorId) {
  const s = dayStats();
  s.views++;
  const h = crypto.createHash('sha256').update(visitorId).digest('hex').slice(0, 16);
  if (!seenSet.has(h) && seenSet.size < MAX_VISITORS_TRACKED) {
    seenSet.add(h); state.stats.seen.ids.push(h); s.visitors++;
  }
  saveSoon();
}
function countEvent(kind) { const s = dayStats(); s[kind] = (s[kind] || 0) + 1; saveSoon(); }

/* ---------- 관리자 인증 ---------- */
const sessions = new Map();   // token -> 만료 시각
const loginFails = new Map(); // ip -> { count, since }

function sha256(s) { return crypto.createHash('sha256').update(String(s), 'utf8').digest(); }
function passwordMatches(input) {
  if (!ADMIN_PASSWORD) return false;
  // 길이 차이로 정보가 새지 않도록 해시끼리 상수 시간 비교
  return crypto.timingSafeEqual(sha256(input), sha256(ADMIN_PASSWORD));
}
function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  // 마지막 값은 Railway 프록시가 붙인 것이라 사용자가 위조할 수 없다
  return (fwd ? String(fwd).split(',').pop() : req.socket.remoteAddress || '').trim();
}
function isLockedOut(ip) {
  const f = loginFails.get(ip);
  if (!f) return false;
  if (Date.now() - f.since > LOGIN_WINDOW_MS) { loginFails.delete(ip); return false; }
  return f.count >= LOGIN_MAX_FAILS;
}
function recordFail(ip) {
  const f = loginFails.get(ip);
  if (!f || Date.now() - f.since > LOGIN_WINDOW_MS) loginFails.set(ip, { count: 1, since: Date.now() });
  else f.count++;
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch {} }
  });
  return out;
}
function isAdmin(req) {
  const token = parseCookies(req).admin_session;
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(token); return false; }
  return true;
}
function cookie(req, name, value, maxAgeSec, httpOnly = true) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `${name}=${value}; ${httpOnly ? 'HttpOnly; ' : ''}SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (now > exp) sessions.delete(t);
  for (const [ip, f] of loginFails) if (now - f.since > LOGIN_WINDOW_MS) loginFails.delete(ip);
}, 10 * 60 * 1000).unref();

/* ---------- HTTP 도우미 ---------- */
function send(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(data === undefined ? '' : JSON.stringify(data));
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(v && typeof v === 'object' ? v : {});
      } catch { reject(Object.assign(new Error('bad json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
// 다른 사이트에서 보낸 변경 요청 막기: Origin이 있으면 우리 호스트와 같아야 함
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
const cleanText = (v, max) => (typeof v === 'string' ? v.replace(/\s+/g, ' ').trim().slice(0, max) : '');

function publicConfig() {
  return {
    notice: state.notice.on && state.notice.text ? { text: state.notice.text } : null,
    event: state.event.openAt ? { title: state.event.title, openAt: state.event.openAt } : null,
    links: state.links,
  };
}
function adminSnapshot() {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = dayFmt.format(new Date(Date.now() - i * 86400000));
    days.push({ day: d, ...EMPTY_DAY(), ...(state.stats.days[d] || {}) });
  }
  return {
    notice: state.notice,
    event: state.event,
    links: state.links,
    stats: { today: days[6], last7: days },
  };
}

/* ---------- API ---------- */
async function handleApi(req, res, urlPath) {
  const m = req.method;
  const admin = isAdmin(req);
  if (m !== 'GET' && m !== 'HEAD') {
    if (!sameOrigin(req)) return send(res, 403, { error: '허용되지 않은 출처의 요청입니다.' });
    if (m !== 'DELETE' && !String(req.headers['content-type'] || '').startsWith('application/json')) {
      return send(res, 415, { error: 'JSON 형식으로 보내 주세요.' });
    }
  }
  const needAdmin = () => send(res, 401, { error: '관리자 로그인이 필요해요.' });

  /* 공개 API */
  if (urlPath === '/api/config' && m === 'GET') return send(res, 200, publicConfig());

  if (urlPath === '/api/track' && m === 'POST') {
    const { e } = await readJson(req);
    if (e === 'captcha' || e === 'seat') countEvent(e);
    return send(res, 204);
  }

  /* 관리자 로그인 */
  if (urlPath === '/api/admin/me' && m === 'GET') {
    return send(res, 200, { loggedIn: admin, configured: Boolean(ADMIN_PASSWORD), ...(admin ? adminSnapshot() : {}) });
  }

  if (urlPath === '/api/admin/login' && m === 'POST') {
    if (!ADMIN_PASSWORD) return send(res, 503, { error: '서버에 ADMIN_PASSWORD 환경변수가 설정되어 있지 않아요.' });
    const ip = clientIp(req);
    if (isLockedOut(ip)) return send(res, 429, { error: '로그인 시도가 너무 많아요. 15분 뒤에 다시 시도해 주세요.' });
    const { password } = await readJson(req);
    if (typeof password !== 'string' || !passwordMatches(password)) {
      recordFail(ip);
      return send(res, 401, { error: '비밀번호가 맞지 않아요.' });
    }
    loginFails.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_TTL_MS);
    return send(res, 200, { loggedIn: true, ...adminSnapshot() }, { 'Set-Cookie': cookie(req, 'admin_session', token, SESSION_TTL_MS / 1000) });
  }

  if (urlPath === '/api/admin/logout' && m === 'POST') {
    const token = parseCookies(req).admin_session;
    if (token) sessions.delete(token);
    return send(res, 200, { loggedIn: false }, { 'Set-Cookie': cookie(req, 'admin_session', '', 0) });
  }

  /* 여기부터는 모두 관리자 전용 */
  if (urlPath.startsWith('/api/admin/') && !admin) return needAdmin();

  if (urlPath === '/api/admin/notice' && m === 'PUT') {
    const b = await readJson(req);
    state.notice = { text: cleanText(b.text, MAX_NOTICE), on: Boolean(b.on) };
    saveNow(); return send(res, 200, state.notice);
  }

  if (urlPath === '/api/admin/event' && m === 'PUT') {
    const b = await readJson(req);
    let openAt = null;
    if (b.openAt !== null && b.openAt !== undefined) {
      openAt = Number(b.openAt);
      if (!Number.isFinite(openAt) || openAt < 946684800000 || openAt > 4102444800000) {
        return send(res, 400, { error: '오픈 일시가 올바르지 않아요.' });
      }
    }
    state.event = { title: cleanText(b.title, MAX_TITLE), openAt };
    saveNow(); return send(res, 200, state.event);
  }

  if (urlPath === '/api/admin/links' && m === 'PUT') {
    const { links } = await readJson(req);
    if (!Array.isArray(links)) return send(res, 400, { error: 'links 목록이 필요해요.' });
    if (links.length > MAX_LINKS) return send(res, 400, { error: `링크는 ${MAX_LINKS}개까지 넣을 수 있어요.` });
    const clean = [];
    for (const [i, l] of links.entries()) {
      const name = cleanText(l && l.name, 20);
      const raw = typeof (l && l.url) === 'string' ? l.url.trim() : '';
      let url;
      try { url = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw); } catch {}
      if (!name) return send(res, 400, { error: `${i + 1}번째 링크의 이름을 입력해 주세요.` });
      // 자바스크립트 링크 등은 막고 http/https 주소만 허용
      if (!url || !/^https?:$/.test(url.protocol) || !url.hostname.includes('.') || url.href.length > 300) {
        return send(res, 400, { error: `${name}: 주소가 올바르지 않아요. https://로 시작하는 주소를 넣어 주세요.` });
      }
      clean.push({ name, url: url.href });
    }
    state.links = clean; saveNow();
    return send(res, 200, { links: state.links });
  }

  if (urlPath === '/api/admin/stats' && m === 'GET') return send(res, 200, adminSnapshot().stats);

  return send(res, 404, { error: '없는 주소예요.' });
}

/* ---------- 정적 파일 ---------- */
function serveStatic(req, res, urlPath) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end();
  }
  let rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  if (rel === 'admin' || rel === 'admin/') rel = 'admin.html';
  const file = path.resolve(ROOT, rel);
  if (!file.startsWith(ROOT + path.sep)) {
    res.writeHead(403);
    return res.end();
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found');
    }
    const headers = {
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      // 시간 보정은 매 응답의 Date 헤더를 쓰므로 캐시를 막는다
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    };
    // 메인 화면 방문 집계 (익명 방문자 ID 쿠키)
    if (rel === 'index.html' && req.method === 'GET') {
      let vid = parseCookies(req).vid;
      if (!vid || !/^[0-9a-f]{32}$/.test(vid)) {
        vid = crypto.randomBytes(16).toString('hex');
        headers['Set-Cookie'] = cookie(req, 'vid', vid, 365 * 86400);
      }
      countView(vid);
    }
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer(async (req, res) => {
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
  catch { res.writeHead(400); return res.end(); }

  if (urlPath === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (urlPath.startsWith('/api/')) {
    try { await handleApi(req, res, urlPath); }
    catch (e) {
      if (!res.headersSent) send(res, e.status || 500, { error: e.status ? '요청 형식이 잘못됐어요.' : '서버 오류가 났어요.' });
      if (!e.status) console.error(e);
    }
    return;
  }
  serveStatic(req, res, urlPath);
});

function shutdown() { saveNow(); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 3000).unref(); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`티켓팅 스탠바이 실행 중: http://localhost:${PORT}`);
  if (!ADMIN_PASSWORD) console.warn('ADMIN_PASSWORD가 설정되지 않아 관리자 로그인이 꺼져 있어요.');
});
