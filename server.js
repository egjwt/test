const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'items.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 관리자 로그인 유지 2시간
const LOGIN_WINDOW_MS = 15 * 60 * 1000;    // 로그인 시도 제한 구간
const LOGIN_MAX_FAILS = 5;                 // 구간당 허용 실패 횟수
const MAX_ITEMS = 200;
const MAX_TEXT = 200;
const MAX_BODY = 10 * 1024;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const DEFAULT_ITEMS = [
  '멜론 계정 로그인 확인 (오픈 10분 전 다시 로그인)',
  '본인인증·회원정보 확인 (본인인증 필수 공연 대비)',
  '결제수단 정하기 · 카드사 앱 로그인 해두기',
  '공연 상세 페이지 미리 열어두기',
  '관람일·회차·매수 정하기',
  '좌석 1·2·3순위 구역 정하기',
  '브라우저 팝업 차단 해제',
  '유선 인터넷 또는 안정적인 와이파이 연결',
  '불필요한 탭·프로그램 닫기',
  '보안문자 연습 3회 이상',
  '대기열 진입 후 새로고침하지 않기',
];

/* ---------- 할 일 저장소 (JSON 파일) ---------- */
const newId = () => crypto.randomBytes(6).toString('hex');
let items;
function loadItems() {
  try {
    items = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!Array.isArray(items)) throw new Error('bad data');
  } catch {
    items = DEFAULT_ITEMS.map(t => ({ id: newId(), t, d: false }));
    saveItems();
  }
}
function saveItems() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(items));
    fs.renameSync(tmp, DATA_FILE);
  } catch (e) {
    console.error('할 일 저장 실패:', e.message);
  }
}
loadItems();

/* ---------- 관리자 인증 ---------- */
const sessions = new Map(); // token -> 만료 시각
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
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
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
function sessionCookie(req, token, maxAgeSec) {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `admin_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (now > exp) sessions.delete(t);
  for (const [ip, f] of loginFails) if (now - f.since > LOGIN_WINDOW_MS) loginFails.delete(ip);
}, 10 * 60 * 1000).unref();

/* ---------- HTTP 도우미 ---------- */
function send(res, status, data, headers = {}) {
  const body = data === undefined ? '' : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
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
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('bad json'), { status: 400 })); }
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

/* ---------- API ---------- */
async function handleApi(req, res, urlPath) {
  const m = req.method;
  if (m !== 'GET' && m !== 'HEAD') {
    if (!sameOrigin(req)) return send(res, 403, { error: '허용되지 않은 출처의 요청입니다.' });
    if (!String(req.headers['content-type'] || '').startsWith('application/json') && m !== 'DELETE') {
      return send(res, 415, { error: 'JSON 형식으로 보내 주세요.' });
    }
  }

  // 공개 API: 할 일 목록
  if (urlPath === '/api/items' && m === 'GET') return send(res, 200, items);

  if (urlPath === '/api/items' && m === 'POST') {
    const { t } = await readJson(req);
    const text = typeof t === 'string' ? t.trim() : '';
    if (!text) return send(res, 400, { error: '내용을 입력해 주세요.' });
    if (text.length > MAX_TEXT) return send(res, 400, { error: `${MAX_TEXT}자 이하로 입력해 주세요.` });
    if (items.length >= MAX_ITEMS) return send(res, 400, { error: `항목은 ${MAX_ITEMS}개까지 만들 수 있어요.` });
    const item = { id: newId(), t: text, d: false };
    items.push(item); saveItems();
    return send(res, 201, item);
  }

  if (urlPath === '/api/items/uncheck-all' && m === 'POST') {
    items.forEach(x => { x.d = false; }); saveItems();
    return send(res, 200, items);
  }

  const one = urlPath.match(/^\/api\/items\/([0-9a-f]{12})$/);
  if (one) {
    const item = items.find(x => x.id === one[1]);
    if (!item) return send(res, 404, { error: '항목을 찾을 수 없어요.' });
    if (m === 'PATCH') {
      const { d } = await readJson(req);
      if (typeof d !== 'boolean') return send(res, 400, { error: 'd는 true 또는 false여야 해요.' });
      item.d = d; saveItems();
      return send(res, 200, item);
    }
    if (m === 'DELETE') {
      items = items.filter(x => x !== item); saveItems();
      return send(res, 204);
    }
  }

  // 관리자 API
  if (urlPath === '/api/admin/me' && m === 'GET') {
    return send(res, 200, { loggedIn: isAdmin(req), configured: Boolean(ADMIN_PASSWORD), count: isAdmin(req) ? items.length : undefined });
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
    return send(res, 200, { loggedIn: true, count: items.length }, { 'Set-Cookie': sessionCookie(req, token, SESSION_TTL_MS / 1000) });
  }

  if (urlPath === '/api/admin/logout' && m === 'POST') {
    const token = parseCookies(req).admin_session;
    if (token) sessions.delete(token);
    return send(res, 200, { loggedIn: false }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }

  if (urlPath === '/api/admin/items' && m === 'DELETE') {
    if (!isAdmin(req)) return send(res, 401, { error: '관리자 로그인이 필요해요.' });
    const removed = items.length;
    items = []; saveItems();
    console.log(`관리자가 할 일 ${removed}개를 모두 삭제함`);
    return send(res, 200, { removed, count: 0 });
  }

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
    res.writeHead(200, {
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      // 시간 보정은 매 응답의 Date 헤더를 쓰므로 캐시를 막는다
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    });
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

server.listen(PORT, '0.0.0.0', () => {
  console.log(`티켓팅 스탠바이 실행 중: http://localhost:${PORT}`);
  if (!ADMIN_PASSWORD) console.warn('ADMIN_PASSWORD가 설정되지 않아 관리자 로그인이 꺼져 있어요.');
});
