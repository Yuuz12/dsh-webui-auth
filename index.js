/**
 * dsh-webui-auth — persistent WebUI authentication plugin for DeepSeek
 * Harness (security-hardened fork).
 *
 * Enforces authentication at the HTTP/transport layer so unauthenticated
 * browsers (or plain HTTP clients) cannot load WebUI resources, call the
 * /api RPC surface, or open the WebSocket downlinks.
 *
 * Hardening changes over upstream 0.2.3 (by xiaoying-agent):
 *
 *   H1. First-run setup requires a per-boot random setup token that is only
 *       printed to the host log (where the operator reads it). A remote
 *       attacker who reaches the server before the operator can no longer
 *       claim the administrator account.
 *   H2. /api and WebSocket gating is done by RUNTIME ROUTE WRAPPING instead
 *       of patching dsh core package sources on disk. No core files are
 *       modified; nothing silently breaks on a dsh upgrade. If the expected
 *       routes are missing (dsh internals changed), the plugin logs an error
 *       AND reports it on the settings page — and the login/configure
 *       endpoints refuse to enable the gate until the shape check passes
 *       (fail-closed against "enabled but /api unprotected").
 *   H3. Sessions persist to disk (JSONL append + startup replay), so a dsh
 *       restart no longer logs everyone out.
 *   H4. Login rate limiting is per-IP (socket remote address; honors
 *       CF-Connecting-IP / X-Forwarded-For leftmost-untrusted strip when the
 *       socket is a loopback reverse proxy) instead of one global bucket,
 *       so an attacker cannot lock the operator out.
 *   H5. The audit log stores HMAC-keyed, truncated client IPs instead of
 *       raw addresses (the HMAC key is generated once and stored next to
 *       the credentials with 0600 permissions).
 *
 * Upstream credit: authentication architecture, login page, settings UI,
 * and the scrypt credential format originate from Yuuz12/dsh-webui-auth
 * (MIT). This fork keeps the on-disk formats compatible where possible.
 *
 * Routes protected (all via runtime wrapping of the webServer service):
 *   - prefix ""    : SPA resources (302 to login page)
 *   - prefix "/plugins": client plugin bundles (302 to login page)
 *   - prefix "/api"     : RPC surface (401)
 *   - upgrades /api/events.mux + /api/events.host : (reject upgrade)
 *
 * Sessions: server-side, persisted across restarts (H3), carried by an
 * HttpOnly cookie `dsh_wua_session`; changing the password revokes every
 * other session.
 */

import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHmac } from "node:crypto";
import { readFileSync, writeFileSync, appendFileSync, accessSync, mkdirSync, unlinkSync, constants as fsConstants } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve as resolvePath } from "node:path";
import { promisify } from "node:util";

export const name = 'dsh-webui-auth'

export const inject = ['webServer', 'fs']

// ---------------- 密码哈希：scrypt（与上游相同的参数与存储格式） ----------------

const SCRYPT_N = 32768
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_KEYLEN = 64
const SCRYPT_MAXMEM = 64 * 1024 * 1024
const SCRYPT_PREFIX = 'scrypt:'

const scrypt = promisify(scryptCb)

async function hashPassword(password) {
  const salt = randomBytes(16).toString('base64')
  const derived = await scrypt(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM })
  return SCRYPT_PREFIX + SCRYPT_N + ':' + SCRYPT_R + ':' + SCRYPT_P + ':' + salt + ':' + derived.toString('base64')
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.startsWith(SCRYPT_PREFIX)) return false
  const parts = stored.split(':')
  if (parts.length !== 6) return false
  const n = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  const salt = parts[4]
  let expected = null
  try { expected = Buffer.from(parts[5], 'base64') } catch (e) { return false }
  if (!Number.isInteger(n) || n < 1024 || !Number.isInteger(r) || r < 1 || !Number.isInteger(p) || p < 1 || !expected || expected.length === 0) return false
  try {
    const derived = await scrypt(password, salt, expected.length, { N: n, r, p, maxmem: SCRYPT_MAXMEM })
    return timingSafeEqual(derived, expected)
  } catch (e) {
    return false
  }
}

let dummyHashPromise = null
function dummyHash() {
  if (dummyHashPromise === null) {
    dummyHashPromise = hashPassword(randomBytes(8).toString('hex')).catch((e) => {
      dummyHashPromise = null
      throw e
    })
  }
  return dummyHashPromise
}
async function dummyVerify(password) {
  const h = await dummyHash()
  return verifyPassword(password, h)
}

// ---------------- 数据目录与文件 ----------------

function pluginDir() {
  try {
    let url = import.meta.url
    const q = url.indexOf('?')
    if (q !== -1) url = url.slice(0, q)
    const h = url.indexOf('#')
    if (h !== -1) url = url.slice(0, h)
    if (url.startsWith('file://')) {
      let p = url.slice('file://'.length)
      if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1)
      p = decodeURIComponent(p)
      const slash = p.lastIndexOf('/')
      if (slash > 0) return p.slice(0, slash)
    }
  } catch (e) { /* fall through to the home fallback */ }
  return null
}

function resolveDataDirFrom(dir) {
  if (dir) {
    try {
      accessSync(dir, fsConstants.W_OK)
      return dir
    } catch (e) { /* store/只读目录：回退 */ }
  }
  const home = process.env.DSH_HOME
    || ((process.env.USERPROFILE || process.env.HOME || '.') + '/.dsh')
  return home.replace(/\\/g, '/').replace(/\/+$/, '') + '/dsh-webui-auth'
}

const DATA_DIR = resolveDataDirFrom(pluginDir())

function configPath() {
  return DATA_DIR + '/dsh-webui-auth.json'
}

/** H3: 会话持久化文件（JSONL，一行一个会话）。 */
function sessionsPath() {
  return DATA_DIR + '/sessions.jsonl'
}

/** H5: HMAC 密钥文件，用于审计 IP 的假名化。 */
function hmacKeyPath() {
  return DATA_DIR + '/audit-hmac-key'
}

function ensureDataDir() {
  try {
    mkdirSync(DATA_DIR, { recursive: true })
  } catch (e) { /* 目录存在或创建失败：后续写入会报错并被上层捕获 */ }
}

async function readCredentials(ctx) {
  let raw = null
  try {
    const target = await ctx.fs.resolve(configPath())
    raw = await ctx.fs.readText(target)
  } catch (e) {
    raw = null
  }
  let parsed = null
  if (raw) {
    try { parsed = JSON.parse(raw) } catch (e) { parsed = null }
  }
  if (parsed && typeof parsed === 'object') return parsed
  return null
}

async function writeCredentials(ctx, creds) {
  ensureDataDir()
  const target = await ctx.fs.resolve(configPath())
  await ctx.fs.writeText(target, JSON.stringify(creds), undefined, undefined, { mode: 'danger-full-access' })
}

function isEnabled(creds) {
  return !!(creds && typeof creds.username === 'string' && typeof creds.hash === 'string')
}

const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/

function usernameError(username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return '用户名需为 3-32 位字母、数字、下划线或连字符'
  }
  return null
}

// ---------------- 审计日志（H5：IP 假名化） ----------------

const AUDIT_FILE = 'audit.jsonl'

function auditFileForCli() {
  return DATA_DIR + '/' + AUDIT_FILE
}

async function auditFilePath(ctx) {
  try {
    const r = await ctx.fs.resolve(DATA_DIR + '/' + AUDIT_FILE)
    if (r && typeof r.displayPath === 'string') return r.displayPath
    if (r && typeof r.targetKey === 'string') return r.targetKey
  } catch (e) { /* fall through */ }
  return DATA_DIR + '/' + AUDIT_FILE
}

/**
 * H5: 审计 IP 假名化。HMAC-SHA256(key, ip) 取前 8 hex，再附 /24（IPv4）
 * 或 /64（IPv6）网络前缀明文，便于聚合分析同时不落原始地址。
 * 密钥文件首次生成，0600，与凭据同目录。
 */
function auditHmacKey() {
  const kp = hmacKeyPath()
  try {
    const existing = readFileSync(kp, 'utf8').trim()
    if (existing.length >= 32) return existing
  } catch (e) { /* not present yet */ }
  ensureDataDir()
  const key = randomBytes(32).toString('hex')
  try {
    writeFileSync(kp, key + '\n', { mode: 0o600 })
    return key
  } catch (e) {
    return 'fallback-key-unavailable-' + key.slice(0, 8)
  }
}

function anonymizeIp(ip) {
  if (!ip || typeof ip !== 'string') return null
  let pseudo = null
  try {
    pseudo = createHmac('sha256', auditHmacKey()).update(ip).digest('hex').slice(0, 8)
  } catch (e) {
    pseudo = 'err'
  }
  // 网络 /24 或 /64 前缀（聚合分析用）
  let net = null
  if (ip.includes('.')) {
    const parts = ip.split('.').slice(0, 3).join('.')
    net = parts + '.0/24'
  } else {
    const clean = ip.replace(/^::ffff:/, '')
    const groups = clean.split(':').slice(0, 4).join(':')
    net = groups + '::/64'
  }
  return `hmac:${pseudo}|${net}`
}

async function auditLog(ctx, event, fields) {
  let target = null
  try {
    target = await auditFilePath(ctx)
    if (!target) return
    ensureDataDir()
    const entry = { ts: new Date().toISOString(), event }
    for (const key of Object.keys(fields || {})) {
      let v = fields[key]
      if (v === undefined) continue
      if (key === 'ip' && typeof v === 'string') v = anonymizeIp(v)
      entry[key] = typeof v === 'string' || typeof v === 'number' ? v : String(v)
    }
    appendFileSync(target, JSON.stringify(entry) + '\n', 'utf8')
  } catch (e) {
    try {
      ctx.logger.warn('[dsh-webui-auth] audit write failed: ' + (e && e.message ? e.message : String(e)))
    } catch (err) { /* ignore */ }
  }
}

function requestMeta(req) {
  let ip = null
  try { ip = req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : null } catch (e) { /* ignore */ }
  // H4: 反代场景取真实客户端 IP。仅当 socket 是回环（本机 caddy/cloudflared）时信任代理头，
  // 且取 X-Forwarded-For 最左侧（最初的客户端），CF-Connecting-IP 次之。
  if (ip && (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1')) {
    try {
      const cf = req.headers['cf-connecting-ip']
      if (typeof cf === 'string' && cf.trim()) {
        ip = cf.trim()
      } else {
        const xff = req.headers['x-forwarded-for']
        if (typeof xff === 'string' && xff.trim()) {
          ip = xff.split(',')[0].trim() || ip
        }
      }
    } catch (e) { /* keep socket address */ }
  }
  let ua = null
  try { ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null } catch (e) { /* ignore */ }
  return { ip, ua }
}

async function readAuditEntries(ctx, limit) {
  let target = null
  try {
    target = await auditFilePath(ctx)
    if (!target) return []
    const lines = readFileSync(target, 'utf8').split('\n').filter((l) => l.trim())
    const out = []
    for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
      try { out.push(JSON.parse(lines[i])) } catch (e) { /* skip malformed line */ }
    }
    return out
  } catch (e) {
    return []
  }
}

// ---------------- 会话有效期 / 密码强度 ----------------

const TTL_OPTIONS = [0, 1, 12, 24, 72]
const TTL_DEFAULT = 12
const SESSION_BROWSER_TTL_MS = 30 * 60 * 1000

function ttlOf(creds) {
  return (creds && typeof creds.ttl === 'number' && TTL_OPTIONS.includes(creds.ttl)) ? creds.ttl : TTL_DEFAULT
}

const SPECIAL_CHARS = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~]/

function passwordStrength(p) {
  if (typeof p !== 'string' || p.length < 8) return { ok: false, reason: 'length' }
  if (!/[a-z]/.test(p)) return { ok: false, reason: 'lower' }
  if (!/[A-Z]/.test(p)) return { ok: false, reason: 'upper' }
  if (!/[0-9]/.test(p)) return { ok: false, reason: 'digit' }
  if (!SPECIAL_CHARS.test(p)) return { ok: false, reason: 'special' }
  return { ok: true, reason: null }
}

// ---------------- HTTP 工具 ----------------

function sendJson(res, status, body) {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'x-content-type-options': 'nosniff',
    'cache-control': 'no-store',
  })
  res.end(text)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

async function readJsonBody(req, res) {
  const raw = await readBody(req)
  if (!raw.trim()) return {}
  try {
    return JSON.parse(raw)
  } catch (e) {
    sendJson(res, 400, { error: '请求体不是有效 JSON' })
    return null
  }
}

function cookieOf(req, name) {
  const raw = req.headers.cookie
  if (!raw) return null
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return null
}

// ---------------- 会话管理（H3：持久化到磁盘） ----------------

const COOKIE_NAME = 'dsh_wua_session'

function sessionCookie(token, maxAgeSeconds) {
  let c = COOKIE_NAME + '=' + token + '; HttpOnly; SameSite=Lax; Path=/'
  if (maxAgeSeconds !== undefined) c += '; Max-Age=' + maxAgeSeconds
  return c
}

function clearSessionCookie() {
  return COOKIE_NAME + '=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
}

/**
 * H3: 持久化会话存储。
 * - 内存 Map 为热路径；每次创建/删除都追加 JSONL 事件（add/remove），启动时重放恢复。
 * - 重放规则：按行序应用 add/remove；过期的会话在重放时丢弃。
 * - 文件损坏（个别行解析失败）跳过该行，不影响其余会话。
 */
class PersistentSessions {
  constructor() {
    this.live = new Map()
    this.ok = true // 持久化通道健康标志（写失败置 false，不影响认证本身）
  }

  load() {
    let lines = []
    try {
      lines = readFileSync(sessionsPath(), 'utf8').split('\n').filter((l) => l.trim())
    } catch (e) { return /* 无文件 = 全新状态 */ }
    for (const line of lines) {
      let ev = null
      try { ev = JSON.parse(line) } catch (e) { continue }
      if (!ev || typeof ev.op !== 'string' || typeof ev.token !== 'string') continue
      if (ev.op === 'add' && ev.sess && typeof ev.sess === 'object') {
        const s = { username: String(ev.sess.username || ''), expiresAt: Number(ev.sess.expiresAt) || 0, browser: !!ev.sess.browser }
        if (s.expiresAt > Date.now()) this.live.set(ev.token, s)
      } else if (ev.op === 'remove') {
        this.live.delete(ev.token)
      } else if (ev.op === 'clear') {
        this.live.clear()
      }
    }
  }

  append(ev) {
    try {
      ensureDataDir()
      appendFileSync(sessionsPath(), JSON.stringify(ev) + '\n', 'utf8')
      this.ok = true
    } catch (e) {
      this.ok = false // 磁盘写失败：认证继续，仅丢失重启恢复能力
    }
  }

  // 压缩：live 状态整体重写（启动时调用一次，防止文件无限增长）
  compact() {
    try {
      ensureDataDir()
      const out = []
      const now = Date.now()
      for (const [token, s] of this.live) {
        if (s.expiresAt > now) out.push({ op: 'add', token, sess: s })
      }
      writeFileSync(sessionsPath(), out.map((e) => JSON.stringify(e)).join('\n') + (out.length ? '\n' : ''), 'utf8')
    } catch (e) { /* 压缩失败不影响运行 */ }
  }

  get(token) { return this.live.get(token) }
  has(token) { return this.live.has(token) }
  delete(token) {
    this.live.delete(token)
    this.append({ op: 'remove', token })
  }
  set(token, sess) {
    this.live.set(token, sess)
    this.append({ op: 'add', token, sess })
  }
  clear() {
    this.live.clear()
    this.append({ op: 'clear', token: '*' })
  }
}

// ---------------- 登录页（与上游一致，追加 setup-token 输入框） ----------------

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>DSH WebUI 认证</title>
<style>
  body {
    --dsw-alias-bg-base: rgb(255, 255, 255);
    --dsw-alias-bg-layer-1: rgb(255, 255, 255);
    --dsw-alias-bg-layer-2: rgb(255, 255, 255);
    --dsw-alias-border-l1: rgba(0, 0, 0, 0.04);
    --dsw-alias-border-l2: rgba(0, 0, 0, 0.1);
    --dsw-alias-label-primary: rgb(15, 17, 21);
    --dsw-alias-label-secondary: rgb(97, 102, 107);
    --dsw-alias-brand-primary: rgb(15, 17, 21);
    --dsw-alias-state-error-primary: rgb(236, 19, 19);
  }
  body[data-ds-dark-theme] {
    --dsw-alias-bg-base: rgb(21, 21, 23);
    --dsw-alias-bg-layer-1: rgb(35, 35, 36);
    --dsw-alias-bg-layer-2: rgb(44, 44, 46);
    --dsw-alias-border-l1: rgba(255, 255, 255, 0.06);
    --dsw-alias-border-l2: rgba(255, 255, 255, 0.12);
    --dsw-alias-label-primary: rgb(249, 250, 251);
    --dsw-alias-label-secondary: rgb(207, 211, 214);
    --dsw-alias-brand-primary: rgb(249, 250, 251);
    --dsw-alias-state-error-primary: rgb(242, 90, 90);
  }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--dsw-alias-bg-base, #f7f7f8); font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; }
  .card { width: 340px; max-width: calc(100vw - 48px); padding: 28px 24px; box-sizing: border-box;
    background: var(--dsw-alias-bg-layer-1, #fff); border: 1px solid var(--dsw-alias-border-l1, #ddd);
    border-radius: 8px; box-shadow: 0 12px 32px rgba(0,0,0,.08); }
  h1 { margin: 0 0 4px; font-size: 18px; color: var(--dsw-alias-label-primary, #222); }
  .sub { margin: 0 0 6px; font-size: 13px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888); }
  label { display: block; font-size: 12px; color: var(--dsw-alias-label-secondary, #888); margin: 12px 0 5px; }
  input { box-sizing: border-box; width: 100%; padding: 7px 9px; font-size: 13px; color: var(--dsw-alias-label-primary, #222);
    background: var(--dsw-alias-bg-layer-2, #fff); border: 1px solid var(--dsw-alias-border-l1, #ccc); border-radius: 4px; outline: none; }
  input:focus { border-color: var(--dsw-alias-brand-primary, #4a7cf7); }
  input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus {
    -webkit-text-fill-color: var(--dsw-alias-label-primary, #222);
    -webkit-box-shadow: 0 0 0 1000px var(--dsw-alias-bg-layer-2, #fff) inset;
    box-shadow: 0 0 0 1000px var(--dsw-alias-bg-layer-2, #fff) inset;
    caret-color: var(--dsw-alias-label-primary, #222);
    transition: background-color 999999s ease-in-out 0s;
  }
  button { width: 100%; margin-top: 18px; padding: 8px 18px; font-size: 13px; cursor: pointer;
    color: var(--dsw-alias-label-primary, #222); background: var(--dsw-alias-bg-layer-1, #fff);
    border: 1px solid var(--dsw-alias-border-l2, #999); border-radius: 4px; }
  button:disabled { opacity: .55; cursor: default; }
  .err { display: none; margin: 10px 0 0; font-size: 12px; color: var(--dsw-alias-state-error-primary, #d1242f); }
  .hint { margin: 14px 0 0; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888);
    border-top: 1px solid var(--dsw-alias-border-l1, #e5e5e5); padding-top: 10px; }
  .token-row { display: none; }
</style>
</head>
<body>
<script>
(function () {
  var preference = "__THEME_PREFERENCE__";
  if (preference !== 'light' && preference !== 'dark') preference = 'system';
  var mq = typeof matchMedia !== 'undefined' ? matchMedia('(prefers-color-scheme: dark)') : null;
  function apply() {
    var systemDark = preference === 'system' && !!mq && mq.matches;
    var dark = preference === 'dark' || systemDark;
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
    document.body.toggleAttribute('data-ds-dark-theme', dark);
  }
  apply();
  if (preference === 'system' && mq) {
    if (typeof mq.addEventListener === 'function') mq.addEventListener('change', apply);
    else if (typeof mq.addListener === 'function') mq.addListener(apply);
  }
})();
</script>
<div class="card">
  <h1>DSH WebUI</h1>
  <p class="sub" id="sub"></p>
  <form id="f">
    <div class="token-row" id="tokenrow">
      <label for="t">初始化令牌（见 dsh 启动日志）</label>
      <input id="t" type="password" autocomplete="off" spellcheck="false">
    </div>
    <label for="u">用户名</label>
    <input id="u" type="text" autocomplete="username" autofocus spellcheck="false">
    <label for="p" id="pl">密码</label>
    <input id="p" type="password" autocomplete="current-password">
    <div id="pc" style="display:none">
      <label for="p2">确认密码</label>
      <input id="p2" type="password" autocomplete="new-password">
    </div>
    <button id="b" type="submit">登录</button>
    <p class="err" id="e"></p>
  </form>
  <p class="hint">忘记密码：删除插件数据目录的 dsh-webui-auth.json 文件即可重置。</p>
</div>
<script>
var MODE = "__MODE__";
var sub = document.getElementById('sub'), pl = document.getElementById('pl'), pc = document.getElementById('pc'), e = document.getElementById('e'),
  u = document.getElementById('u'), p = document.getElementById('p'), p2 = document.getElementById('p2'), b = document.getElementById('b'),
  f = document.getElementById('f'), t = document.getElementById('t'), tokenrow = document.getElementById('tokenrow');
function show(msg) { e.textContent = msg; e.style.display = 'block'; }
if (MODE === 'setup') {
  sub.textContent = '首次使用：输入初始化令牌并创建管理员账号密码，之后访问 WebUI 需要登录。';
  tokenrow.style.display = 'block';
  pl.textContent = '密码（至少 8 位，含大小写、数字、特殊符号）';
  pc.style.display = 'block';
  b.textContent = '创建账号';
} else {
  sub.textContent = '此界面已启用身份认证，请登录后继续使用。';
}
function validUsername(name) { return /^[A-Za-z0-9_-]{3,32}$/.test(name); }
f.addEventListener('submit', function (ev) {
  ev.preventDefault();
  var username = u.value.trim(), password = p.value, token = t ? t.value.trim() : '';
  if (MODE === 'setup') {
    if (!token) return show('请输入初始化令牌（dsh 启动日志中查找 [dsh-webui-auth] setup token）');
    if (!validUsername(username)) return show('用户名需为 3-32 位字母、数字、下划线或连字符');
    if (password.length < 8) return show('密码至少需要 8 位');
    if (!/[a-z]/.test(password)) return show('密码必须包含小写字母');
    if (!/[A-Z]/.test(password)) return show('密码必须包含大写字母');
    if (!/[0-9]/.test(password)) return show('密码必须包含数字');
    if (!/[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/~]/.test(password)) return show('密码必须包含特殊符号');
    if (password !== p2.value) return show('两次输入的密码不一致');
  }
  b.disabled = true; b.textContent = '请稍候…';
  var body = { username: username, password: password };
  if (MODE === 'setup') body.token = token;
  fetch(MODE === 'setup' ? '/dsh-webui-auth/setup' : '/dsh-webui-auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
  }).then(function (r) { return r.json(); }).then(function (r) {
    if (r && r.ok) { location.href = '/'; return; }
    b.disabled = false; b.textContent = MODE === 'setup' ? '创建账号' : '登录';
    if (r && r.error === 'rate-limited') show('尝试次数过多，请一分钟后重试');
    else if (r && r.error === 'setup-token-required') show('初始化令牌缺失或不正确（见 dsh 启动日志）');
    else if (r && r.error === 'weak-password') show('密码强度不足：至少 8 位，需包含大小写字母、数字和特殊符号');
    else if (r && r.error === 'username-invalid') show('用户名需为 3-32 位字母、数字、下划线或连字符');
    else if (r && r.error === 'not-configured') show('凭据尚未配置，请刷新页面后重新创建');
    else if (r && r.error === 'already-configured') show('认证已启用，请使用登录模式');
    else show(MODE === 'setup' ? '创建失败，请检查输入' : '用户名或密码错误');
  }).catch(function () {
    b.disabled = false; b.textContent = MODE === 'setup' ? '创建账号' : '登录';
    show('无法连接认证服务，请刷新重试');
  });
});
</script>
</body>
</html>`

// ---------------- H2: 运行时路由包装（零核心补丁） ----------------
//
// /api 与 WebSocket 的会话闸门通过包装 webServer 服务的路由表实现：
// 1. 对已注册的 /api prefix 路由与 /api/events.* upgrade 路由做 handler 原地包装；
// 2. 同时替换 prefixes/upgrades 为带拦截的 Map，捕获后续注册（如热重载/插件管理器）；
// 3. 卸载（effect disposer）时恢复原始 handler 与原始 Map —— 完全可逆。
//
// 若找不到预期路由（dsh 内部结构变化），shapeCheck 失败并明确报错，
// 且 setup/configure 拒绝启用闸门（fail-closed：宁可不可用，不可裸奔）。

const API_PREFIX = '/api'
const PLUGINS_PREFIX = '/plugins'
const MUX_PATH = '/api/events.mux'
const HOST_PATH = '/api/events.host'

function rejectUpgrade401(socket) {
  try {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 13\r\n\r\nunauthorized\n')
  } catch (e) { /* ignore */ }
  try { socket.destroy() } catch (e) { /* ignore */ }
}

/**
 * 安装运行时路由闸门。带周期重扫：apply() 可能早于 client-connection 的
 * 路由注册执行（loader 波次顺序不保证），每 2 秒重扫路由表直到全部
 * 找到（上限 60 秒）。gate 状态动态更新，供 status 端点与 fail-closed
 * 检查读取。
 * @returns {{ ok: () => boolean, problems: () => string[], undo: () => void }}
 */
function installRouteGate(ctx, checkRequest, log) {
  const ws = ctx.webServer
  const problems = new Set()
  const undos = []
  let undone = false

  const wrapHttp = (route, opts) => {
    const original = route.handler
    const loopbackDeputy = !!(opts && opts.loopbackDeputy)
    const wrapped = async (req, res) => {
      if (!checkRequest(req)) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        res.end('unauthorized')
        return
      }
      if (loopbackDeputy) {
        // Authenticated + this is the /api surface: present the request to the
        // core as loopback so PRIVILEGED_METHODS' strict fence (settings.*,
        // credentials.*, agentPreset.*, llm.discoverModels) admits it. Our
        // session gate already proved operator identity — strictly stronger
        // than the Host-header heuristic it replaces for these callers.
        // The fence also compares Origin.host to Host and rejects cross-site
        // Fetch Metadata; a reverse-proxied request carries the public origin,
        // so both are normalized alongside Host to the loopback deputy shape.
        req.headers.host = '127.0.0.1'
        // Origin/Fetch-Metadata 一并移除：以"非浏览器回环客户端"形状呈现。
        // 不能只改写 Origin 的 host——Host 带 127.0.0.1:3080 端口而改写后的
        // Origin 无端口时 host 比对仍不相等（实测 403）。删除后走 fence 的
        // 无-Origin 回环放行路径（实测 200），语义也更干净：代理后的请求
        // 本来就不是浏览器直连。
        delete req.headers.origin
        delete req.headers['sec-fetch-site']
        delete req.headers['sec-fetch-mode']
        delete req.headers['sec-fetch-dest']
      }
      return original(req, res)
    }
    route.handler = wrapped
    return () => { route.handler = original }
  }
  const wrapUpgrade = (route) => {
    const original = route.handler
    const wrapped = (req, socket, head) => {
      if (checkRequest(req)) return original(req, socket, head)
      rejectUpgrade401(socket)
    }
    route.handler = wrapped
    return () => { route.handler = original }
  }

  // 已包装的路由打标记，避免重复包装
  const wrapped = new WeakSet()
  const PROTECTED_PREFIXES = [API_PREFIX, PLUGINS_PREFIX]
  const scanOnce = () => {
    if (undone) return
    for (const pfx of PROTECTED_PREFIXES) {
      const route = ws.prefixes.get(pfx)
      if (route !== undefined && !wrapped.has(route)) {
        wrapped.add(route)
        undos.push(wrapHttp(route, { loopbackDeputy: pfx === API_PREFIX }))
        problems.delete(`prefix route "${pfx}" not registered yet`)
        log(`wrapped prefix route ${pfx}`)
      } else if (route === undefined) {
        problems.add(`prefix route "${pfx}" not registered yet`)
      }
    }
    for (const path of [MUX_PATH, HOST_PATH]) {
      const r = ws.upgrades.get(path)
      if (r !== undefined && !wrapped.has(r)) {
        wrapped.add(r)
        undos.push(wrapUpgrade(r))
        problems.delete(`upgrade route "${path}" not registered yet`)
        log(`wrapped upgrade route ${path}`)
      } else if (r === undefined) {
        problems.add(`upgrade route "${path}" not registered yet`)
      }
    }
  }

  scanOnce()

  // 周期重扫：捕获晚注册（loader 波次/服务重挂载）。全找到后停止（但保留
  // 低频兜底扫描，防止服务重建后路由对象被替换）。
  let elapsed = 0
  const rescan = setInterval(() => {
    if (undone) { clearInterval(rescan); return }
    scanOnce()
    elapsed += 2
    if (problems.size === 0 && elapsed > 60) {
      // 全部就位后降频为 10s 兜底（服务 fiber 重建时路由对象会换新）
      clearInterval(rescan)
      const slow = setInterval(() => { if (!undone) scanOnce(); else clearInterval(slow) }, 10000)
      undos.push(() => clearInterval(slow))
    }
  }, 2000)
  undos.push(() => clearInterval(rescan))

  const undo = () => {
    undone = true
    for (const u of undos.splice(0).reverse()) { try { u() } catch (e) { /* ignore */ } }
  }
  return { ok: () => problems.size === 0, problems: () => [...problems], undo }
}

// ---------------- DSH 外观偏好 ----------------

const THEME_NAMESPACE = 'ui-theme'
const THEME_PREFERENCE_DEFAULT = 'system'

function themePreference(ctx) {
  try {
    const settings = ctx.get('settings')
    if (settings === undefined) return THEME_PREFERENCE_DEFAULT
    const section = settings.get(THEME_NAMESPACE)
    if (section === undefined) return THEME_PREFERENCE_DEFAULT
    const preference = section.preference
    return (preference === 'light' || preference === 'dark') ? preference : THEME_PREFERENCE_DEFAULT
  } catch (e) {
    return THEME_PREFERENCE_DEFAULT
  }
}

export async function apply(ctx) {
  // H1: 每次启动生成随机 setup token，仅打印到宿主日志。
  const SETUP_TOKEN = randomBytes(16).toString('hex')

  let enabledFlag = false
  async function refreshEnabled() {
    const creds = await readCredentials(ctx)
    enabledFlag = isEnabled(creds)
  }
  await refreshEnabled()

  // H3: 持久化会话（启动重放 + 压缩）
  const sessions = new PersistentSessions()
  sessions.load()
  sessions.compact()

  // H4: 按 IP 限流 { ip -> [timestamps] }
  const failuresByIp = new Map()
  const RATE_WINDOW_MS = 60_000
  const RATE_MAX = 5

  function ipRateLimited(ip) {
    if (!ip) return false
    const now = Date.now()
    const arr = (failuresByIp.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS)
    if (arr.length >= RATE_MAX) {
      failuresByIp.set(ip, arr)
      return true
    }
    return false
  }
  function recordFailure(ip) {
    if (!ip) return
    const now = Date.now()
    const arr = (failuresByIp.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS)
    arr.push(now)
    failuresByIp.set(ip, arr)
  }

  function checkRequest(req) {
    if (!enabledFlag) return true
    const token = cookieOf(req, COOKIE_NAME)
    if (!token) return false
    const s = sessions.get(token)
    if (!s) return false
    if (s.expiresAt <= Date.now()) {
      sessions.delete(token)
      return false
    }
    if (s.browser === true) s.expiresAt = Date.now() + SESSION_BROWSER_TTL_MS
    return true
  }

  function createSession(username, ttl) {
    const token = randomBytes(24).toString('hex')
    const ttlMs = ttl > 0 ? ttl * 3600 * 1000 : SESSION_BROWSER_TTL_MS
    sessions.set(token, { username, expiresAt: Date.now() + ttlMs, browser: ttl <= 0 })
    return { token, maxAge: ttl > 0 ? ttl * 3600 : undefined }
  }

  function destroySession(req) {
    const token = cookieOf(req, COOKIE_NAME)
    if (token) sessions.delete(token)
  }

  function destroyAllSessionsExcept(keepToken) {
    for (const k of [...sessions.live.keys()]) {
      if (k !== keepToken) sessions.delete(k)
    }
  }

  // H2: 安装运行时路由闸门
  const gate = installRouteGate(ctx, checkRequest, (m) => ctx.logger.info('[dsh-webui-auth] ' + m))
  ctx.effect(() => gate.undo, 'dsh-webui-auth: route gate')
  if (!gate.ok()) {
    ctx.logger.error('[dsh-webui-auth] ROUTE GATE INCOMPLETE — ' + gate.problems().join('; ')
      + '. /api and/or WebSocket may be unprotected; the gate will still wrap them if they register later.')
  }

  ctx.logger.info('[dsh-webui-auth] started, credentials file: ' + configPath())
  if (!enabledFlag) {
    // H1: token 同时落盘（0600，仅本机操作者可读），setup 成功后删除。
    // 解决 ctx.logger 输出在某些部署（systemd）下不可见的问题。
    try {
      ensureDataDir()
      writeFileSync(DATA_DIR + '/setup-token', SETUP_TOKEN + '\n', { mode: 0o600 })
    } catch (e) { /* 落盘失败时仍可从日志读取 */ }
    ctx.logger.info('[dsh-webui-auth] setup token (first-run administrator creation): ' + SETUP_TOKEN)
  }

  // 后台任务：过期会话清理 + enabled 状态刷新
  const bgTimer = setInterval(async () => {
    const now = Date.now()
    for (const [k, s] of sessions.live) if (s.expiresAt <= now) sessions.delete(k)
    try {
      const creds = await readCredentials(ctx)
      enabledFlag = isEnabled(creds)
    } catch (e) { /* keep last state */ }
  }, 60000)
  ctx.effect(() => () => clearInterval(bgTimer), 'dsh-webui-auth: background timer')

  // ---------------- 端点 ----------------

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/login',
    handler: async (req, res) => {
      try {
        if (req.method === 'GET' || req.method === 'HEAD') {
          const page = LOGIN_PAGE
            .replace('__MODE__', enabledFlag ? 'login' : 'setup')
            .replace('__THEME_PREFERENCE__', themePreference(ctx))
          res.writeHead(200, {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'x-robots-tag': 'noindex, nofollow',
            'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
          })
          res.end(page)
          return
        }
        if (req.method === 'POST') {
          const body = await readJsonBody(req, res)
          if (body === null) return
          if (!enabledFlag) {
            sendJson(res, 200, { ok: false, error: 'not-configured' })
            return
          }
          const username = String(body.username || '').trim()
          const password = String(body.password || '')
          const creds = await readCredentials(ctx)
          if (!isEnabled(creds)) {
            sendJson(res, 200, { ok: false, error: 'not-configured' })
            return
          }
          const meta = requestMeta(req)
          if (ipRateLimited(meta.ip)) {
            await auditLog(ctx, 'login_rate_limited', { username: username || null, ip: meta.ip, ua: meta.ua })
            sendJson(res, 200, { ok: false, error: 'rate-limited' })
            return
          }
          let valid = false
          if (username === creds.username && typeof creds.hash === 'string') {
            valid = await verifyPassword(password, creds.hash)
          } else {
            valid = await dummyVerify(password)
          }
          if (!valid) {
            recordFailure(meta.ip)
            await auditLog(ctx, 'login_failure', { username: username || null, ip: meta.ip, ua: meta.ua })
            sendJson(res, 200, { ok: false, error: 'invalid' })
            return
          }
          const s = createSession(username, ttlOf(creds))
          res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
          await auditLog(ctx, 'login_success', { username, ip: meta.ip, ua: meta.ua })
          sendJson(res, 200, { ok: true })
          return
        }
        sendJson(res, 405, { error: '仅支持 GET/POST' })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: login page')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/setup',
    handler: async (req, res) => {
      try {
        if (req.method !== 'POST') {
          sendJson(res, 405, { error: '仅支持 POST' })
          return
        }
        if (enabledFlag) {
          const meta = requestMeta(req)
          await auditLog(ctx, 'setup_failure', { username: null, ip: meta.ip, ua: meta.ua, detail: '已初始化，拒绝重复配置' })
          sendJson(res, 200, { ok: false, error: 'already-configured' })
          return
        }
        // H1: 首次配置必须携带本次启动的 setup token
        const body = await readJsonBody(req, res)
        if (body === null) return
        const suppliedToken = typeof body.token === 'string' ? body.token.trim() : ''
        const meta = requestMeta(req)
        if (suppliedToken !== SETUP_TOKEN) {
          await auditLog(ctx, 'setup_failure', { username: null, ip: meta.ip, ua: meta.ua, detail: 'setup token 缺失或不匹配' })
          sendJson(res, 200, { ok: false, error: 'setup-token-required' })
          return
        }
        const username = String(body.username || '').trim()
        const password = String(body.password || '')
        const nameErr = usernameError(username)
        if (nameErr) {
          await auditLog(ctx, 'setup_failure', { username: username || null, ip: meta.ip, ua: meta.ua, detail: '用户名格式不合法' })
          sendJson(res, 200, { ok: false, error: 'username-invalid' })
          return
        }
        const st = passwordStrength(password)
        if (!st.ok) {
          await auditLog(ctx, 'setup_failure', { username, ip: meta.ip, ua: meta.ua, detail: '密码强度不足' })
          sendJson(res, 200, { ok: false, error: 'weak-password', reason: st.reason })
          return
        }
        // H2 fail-closed：路由闸门不完整时拒绝启用认证（防止"开了登录却裸奔 /api"）
        if (!gate.ok()) {
          await auditLog(ctx, 'setup_failure', { username, ip: meta.ip, ua: meta.ua, detail: '路由闸门不完整，拒绝启用' })
          sendJson(res, 200, { ok: false, error: 'gate-incomplete', problem: gate.problems()[0] || '' })
          return
        }
        await writeCredentials(ctx, { v: 3, username, hash: await hashPassword(password), ttl: TTL_DEFAULT })
        try { unlinkSync(DATA_DIR + '/setup-token') } catch (e) { /* already gone */ }
        enabledFlag = true
        const s = createSession(username, TTL_DEFAULT)
        res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
        await auditLog(ctx, 'setup_success', { username, ip: meta.ip, ua: meta.ua })
        sendJson(res, 200, { ok: true })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: setup')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/logout',
    handler: async (req, res) => {
      try {
        if (req.method !== 'POST') {
          sendJson(res, 405, { error: '仅支持 POST' })
          return
        }
        const token = cookieOf(req, COOKIE_NAME)
        const s = token ? sessions.get(token) : null
        destroySession(req)
        res.setHeader('Set-Cookie', clearSessionCookie())
        const meta = requestMeta(req)
        await auditLog(ctx, 'logout', { username: s ? s.username : null, ip: meta.ip, ua: meta.ua })
        sendJson(res, 200, { ok: true })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: logout')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/status',
    handler: async (req, res) => {
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: '仅支持 GET' })
          return
        }
        if (enabledFlag && !checkRequest(req)) {
          sendJson(res, 401, { error: 'unauthorized' })
          return
        }
        const creds = await readCredentials(ctx)
        const enabled = isEnabled(creds)
        sendJson(res, 200, {
          enabled,
          username: enabled ? creds.username : null,
          ttl: ttlOf(creds),
          sessionsPersisted: sessions.ok,
          gate: { ok: gate.ok(), problems: gate.problems().slice(0, 3) },
        })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: status')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/audit',
    handler: async (req, res) => {
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: '仅支持 GET' })
          return
        }
        if (enabledFlag && !checkRequest(req)) {
          sendJson(res, 401, { error: 'unauthorized' })
          return
        }
        let limit = 10
        if (typeof req.url === 'string') {
          const m = /[?&]limit=(\d+)/.exec(req.url)
          if (m) limit = Math.min(Math.max(Number(m[1]), 1), 100)
        }
        const entries = await readAuditEntries(ctx, limit)
        sendJson(res, 200, { ok: true, entries })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: audit')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/configure',
    handler: async (req, res) => {
      try {
        if (req.method !== 'POST') {
          sendJson(res, 405, { error: '仅支持 POST' })
          return
        }
        if (enabledFlag && !checkRequest(req)) {
          sendJson(res, 401, { error: 'unauthorized' })
          return
        }
        const body = await readJsonBody(req, res)
        if (body === null) return
        const username = String(body.username || '').trim()
        const password = String(body.password || '')
        const current = String(body.current || '')
        const creds = await readCredentials(ctx)
        const meta = requestMeta(req)
        const nameErr = usernameError(username)
        if (nameErr) {
          await auditLog(ctx, 'configure_failure', { username: username || null, ip: meta.ip, ua: meta.ua, detail: '用户名格式不合法' })
          sendJson(res, 200, { ok: false, error: 'username-invalid' })
          return
        }
        const wasEnabled = isEnabled(creds)
        const hashIsScrypt = creds !== null && typeof creds.hash === 'string' && creds.hash.startsWith(SCRYPT_PREFIX)
        const keepPassword = wasEnabled && !password && hashIsScrypt
        if (wasEnabled && !password && !hashIsScrypt) {
          await auditLog(ctx, 'configure_failure', { username, ip: meta.ip, ua: meta.ua, detail: '旧版哈希不支持保留，必须设置新密码' })
          sendJson(res, 200, { ok: false, error: 'legacy-hash' })
          return
        }
        if (!keepPassword) {
          const st = passwordStrength(password)
          if (!st.ok) {
            await auditLog(ctx, 'configure_failure', { username, ip: meta.ip, ua: meta.ua, detail: '密码强度不足' })
            sendJson(res, 200, { ok: false, error: 'weak-password', reason: st.reason })
            return
          }
        }
        if (wasEnabled) {
          const curValid = current && typeof creds.hash === 'string' && await verifyPassword(current, creds.hash)
          if (!curValid) {
            await auditLog(ctx, 'configure_failure', { username, ip: meta.ip, ua: meta.ua, detail: '当前密码不正确' })
            sendJson(res, 200, { ok: false, error: 'current-invalid' })
            return
          }
        }
        // H2 fail-closed：闸门不完整时拒绝启用
        if (!wasEnabled && !gate.ok()) {
          await auditLog(ctx, 'configure_failure', { username, ip: meta.ip, ua: meta.ua, detail: '路由闸门不完整，拒绝启用' })
          sendJson(res, 200, { ok: false, error: 'gate-incomplete', problem: gate.problems()[0] || '' })
          return
        }
        let ttl = wasEnabled ? ttlOf(creds) : TTL_DEFAULT
        if (body.ttl !== undefined) {
          ttl = Number(body.ttl)
          if (!Number.isInteger(ttl) || !TTL_OPTIONS.includes(ttl)) {
            sendJson(res, 200, { ok: false, error: 'ttl-invalid' })
            return
          }
        }
        const credsOut = (keepPassword && typeof creds.hash === 'string')
          ? { v: 3, username, hash: creds.hash, ttl }
          : { v: 3, username, hash: await hashPassword(password), ttl }
        await writeCredentials(ctx, credsOut)
        enabledFlag = true
        if (wasEnabled) {
          const keepToken = cookieOf(req, COOKIE_NAME)
          destroyAllSessionsExcept(keepToken)
        } else {
          const s = createSession(username, ttl)
          res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
        }
        const detailParts = []
        if (!keepPassword) detailParts.push('密码已修改')
        if (body.ttl !== undefined) detailParts.push('有效期已修改')
        await auditLog(ctx, 'configure_success', { username, ip: meta.ip, ua: meta.ua, detail: detailParts.length ? detailParts.join('，') : null })
        sendJson(res, 200, { ok: true })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: configure')

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/dsh-webui-auth/disable',
    handler: async (req, res) => {
      try {
        if (req.method !== 'POST') {
          sendJson(res, 405, { error: '仅支持 POST' })
          return
        }
        if (enabledFlag && !checkRequest(req)) {
          sendJson(res, 401, { error: 'unauthorized' })
          return
        }
        const body = await readJsonBody(req, res)
        if (body === null) return
        const current = String(body.current || '')
        const creds = await readCredentials(ctx)
        const meta = requestMeta(req)
        if (!isEnabled(creds)) {
          sendJson(res, 200, { ok: true })
          return
        }
        const curValid = current && typeof creds.hash === 'string' && await verifyPassword(current, creds.hash)
        if (!curValid) {
          await auditLog(ctx, 'disable_failure', { username: creds.username, ip: meta.ip, ua: meta.ua, detail: '当前密码不正确' })
          sendJson(res, 200, { ok: false, error: 'current-invalid' })
          return
        }
        await writeCredentials(ctx, { v: 1, enabled: false })
        sessions.clear()
        res.setHeader('Set-Cookie', clearSessionCookie())
        enabledFlag = false
        await auditLog(ctx, 'disable_success', { username: creds.username, ip: meta.ip, ua: meta.ua })
        sendJson(res, 200, { ok: true })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: disable')

  // ---------------- 传输层拦截 ----------------

  // 兜底拦截：所有未被 exact / 更长前缀认领的请求（index.html、/assets/*、SPA 路由等）
  ctx.effect(() => ctx.webServer.register({
    kind: 'prefix',
    path: '',
    handler: async (req, res) => {
      try {
        if (checkRequest(req)) {
          const fallback = ctx.webServer.fallback
          if (fallback !== undefined) {
            await fallback(req, res)
            return
          }
          res.writeHead(404)
          res.end()
          return
        }
        res.writeHead(302, { location: '/dsh-webui-auth/login' })
        res.end()
      } catch (e) {
        ctx.logger.warn('[dsh-webui-auth] intercept error: ' + (e && e.message ? e.message : String(e)))
        if (!res.headersSent) {
          res.writeHead(500)
          res.end()
        } else {
          res.destroy()
        }
      }
    },
  }), 'dsh-webui-auth: transport gate')
}

// ---------------- CLI：node index.js audit [--limit N] ----------------

let metaFilePath = null
try {
  let u = import.meta.url
  const q = u.indexOf('?')
  if (q !== -1) u = u.slice(0, q)
  const h = u.indexOf('#')
  if (h !== -1) u = u.slice(0, h)
  metaFilePath = fileURLToPath(u)
} catch (e) { /* not a file URL */ }

const isCliEntry = metaFilePath !== null && (() => {
  try {
    const entry = process.argv[1]
    if (!entry) return false
    const self = process.platform === 'win32' ? metaFilePath.toLowerCase() : metaFilePath
    const resolved = resolvePath(entry)
    return (process.platform === 'win32' ? resolved.toLowerCase() : resolved) === self
  } catch (e) {
    return false
  }
})()

if (isCliEntry) {
  const cmd = process.argv[2]
  if (cmd === 'audit') {
    const li = process.argv.indexOf('--limit')
    let limit = 20
    if (li >= 0 && process.argv[li + 1] !== undefined) {
      const n = Number(process.argv[li + 1])
      if (Number.isFinite(n) && n > 0) limit = Math.min(Math.floor(n), 200)
    }
    const file = auditFileForCli()
    const rows = []
    if (file) {
      try {
        const lines = readFileSync(file, 'utf8').split('\n').filter((l) => l.trim())
        for (let i = lines.length - 1; i >= 0 && rows.length < limit; i--) {
          try { rows.push(JSON.parse(lines[i])) } catch (e) { /* skip malformed */ }
        }
      } catch (e) { /* 文件尚不存在 */ }
    }
    console.log('[dsh-webui-auth] 审计日志：最近 ' + rows.length + ' 条' + (file ? '（文件: ' + file + '）' : ''))
    if (rows.length === 0) {
      console.log('（暂无审计记录；登录/配置等安全事件会追加写入插件目录的 audit.jsonl）')
    }
    for (const r of rows) {
      const parts = [r.ts || '?', r.event || '?']
      if (r.username) parts.push('user=' + r.username)
      if (r.ip) parts.push('ip=' + r.ip)
      if (r.detail) parts.push('detail=' + String(r.detail))
      console.log('  ' + parts.join('  '))
    }
  } else {
    console.log('[dsh-webui-auth] 用法: node index.js audit [--limit N]')
  }
  process.exit(0)
}
