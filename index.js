/**
 * dsh-webui-auth — persistent WebUI authentication plugin for DeepSeek
 * Harness (hardened build).
 *
 * Enforces authentication at the HTTP/transport layer so unauthenticated
 * browsers (or plain HTTP clients) cannot load WebUI resources, call the
 * /api RPC surface, or open the WebSocket downlinks:
 *
 *   1. `prefix ''` fallback route intercepts every unclaimed request
 *      (index.html, /assets/*, SPA routes, unknown paths): no valid session
 *      cookie -> 302 to the login page; valid session -> hand off to the SPA
 *      fallback (frontend-static) which serves the dist.
 *   2. `prefix '/plugins/'` intercepts client plugin bundles and serves them
 *      itself after the same session check (client-modules' shorter
 *      "/plugins" route is shadowed by longest-prefix matching).
 *   3. /api RPC and the WebSocket upgrades are gated by a minimal patch in
 *      dsh-client-connection: it consults `webServer.webuiAuthGate`, which
 *      this plugin mounts on the shared webServer service instance.
 *   4. Sessions are server-side (in-memory), carried by an HttpOnly cookie
 *      `dsh_wua_session`; changing the password revokes every other session.
 *
 * First-run flow: while no credentials exist, authentication is off
 * (enabledFlag false -> everything passes). The login page then renders the
 * "create administrator account" form; creating credentials enables the gate
 * immediately and opens a session.
 *
 * Credentials live in the plugin's own folder (`dsh-webui-auth.json` next to
 * this module) as a salted SHA-256 hash — never plaintext.
 *
 * Endpoints:
 *   GET  /dsh-webui-auth/login       login page (public, mode by enabled state)
 *   POST /dsh-webui-auth/login       { username, password }   -> { ok, error? }
 *   POST /dsh-webui-auth/setup       { username, password }   -> { ok, error? } (first-run only)
 *   POST /dsh-webui-auth/logout      (session required)       -> { ok }
 *   GET  /dsh-webui-auth/status      (session required)       -> { enabled, username, ttl }
 *   POST /dsh-webui-auth/configure   (session required) { username, password?, current, ttl? }
 *   POST /dsh-webui-auth/disable     (session required) { current }
 */

import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";

export const name = 'dsh-webui-auth'

export const inject = ['webServer', 'fs', 'clientModules']

// ---------------- SHA-256（手写实现，UTF-8 感知，已通过 NIST 测试向量验证） ----------------

let H = null
let K = null

function sha256(input) {
  // input: byte string（每个字符码 0-255）
  const rotateRight = (n, b) => (n >>> b) | (n << (32 - b))
  const maxWord = Math.pow(2, 32)
  let result = ''
  const words = []
  const bitLength = input.length * 8
  if (H === null) {
    H = []
    K = []
    let primeCounter = 0
    const isComposite = {}
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate
        H[primeCounter] = (Math.pow(candidate, 0.5) * maxWord) | 0
        K[primeCounter++] = (Math.pow(candidate, 1 / 3) * maxWord) | 0
      }
    }
  }
  let hash = H.slice()
  input += '\x80'
  while (input.length % 64 - 56) input += '\x00'
  for (let i = 0; i < input.length; i++) {
    const j = input.charCodeAt(i)
    if (j >> 8) return ''
    words[i >> 2] |= j << (((3 - i) % 4) * 8)
  }
  words[words.length] = (bitLength / maxWord) | 0
  words[words.length] = bitLength
  for (let j = 0; j < words.length;) {
    const w = words.slice(j, (j += 16))
    const oldHash = hash.slice(0, 8)
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15]
      const w2 = w[i - 2]
      const a = hash[0]
      const e = hash[4]
      const temp1 = hash[7]
        + (rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25))
        + ((e & hash[5]) ^ (~e & hash[6]))
        + K[i]
        + (w[i] = (i < 16) ? w[i] : (
            w[i - 16]
            + (rotateRight(w15, 7) ^ rotateRight(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rotateRight(w2, 17) ^ rotateRight(w2, 19) ^ (w2 >>> 10))
          ) | 0)
      const temp2 = (rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]))
      const next = [(temp1 + temp2) | 0].concat(hash)
      next[4] = (next[4] + temp1) | 0
      hash = next
    }
    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0
  }
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255
      result += ((b < 16) ? '0' : '') + b.toString(16)
    }
  }
  return result
}

function utf8Bytes(str) {
  let out = ''
  const bytes = new TextEncoder().encode(str)
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i])
  return out
}

// 启动自检：NIST 测试向量
function selfTest() {
  const a = sha256(utf8Bytes('abc'))
  const b = sha256(utf8Bytes(''))
  return a === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    && b === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
}

// ---------------- 配置（凭据）存储 ----------------

/**
 * The plugin's own directory, derived from import.meta.url (pure string ops,
 * no imports). The credentials document lives next to the module so
 * uninstalling the plugin folder leaves no residue.
 */
function pluginDir() {
  try {
    let url = import.meta.url
    const q = url.indexOf('?')
    if (q !== -1) url = url.slice(0, q)
    const h = url.indexOf('#')
    if (h !== -1) url = url.slice(0, h)
    if (url.startsWith('file://')) {
      let p = url.slice('file://'.length)
      if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1) // Windows: '/C:/...' -> 'C:/...'
      p = decodeURIComponent(p)
      const slash = p.lastIndexOf('/')
      if (slash > 0) return p.slice(0, slash)
    }
  } catch (e) { /* fall through to the home fallback */ }
  return null
}

function configPath() {
  const dir = pluginDir()
  if (dir) return dir + '/dsh-webui-auth.json'
  // Fallback for exotic loaders where import.meta.url is not a file URL.
  const home = process.env.DSH_HOME
    || ((process.env.USERPROFILE || process.env.HOME || '.') + '/.dsh')
  return home.replace(/\\/g, '/').replace(/\/+$/, '') + '/dsh-webui-auth.json'
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
  const target = await ctx.fs.resolve(configPath())
  await ctx.fs.writeText(target, JSON.stringify(creds), undefined, undefined, { mode: 'danger-full-access' })
}

function isEnabled(creds) {
  return !!(creds && typeof creds.username === 'string' && typeof creds.hash === 'string')
}

function hashPassword(salt, password) {
  return sha256(salt + ':' + utf8Bytes(password))
}

function randomSalt() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  let out = ''
  for (let i = 0; i < 24; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

// 认证有效期（小时）：0 = 浏览器会话（关闭浏览器后失效）
const TTL_OPTIONS = [0, 1, 12, 24, 72]
const TTL_DEFAULT = 12
const SESSION_BROWSER_TTL_MS = 30 * 60 * 1000 // ttl=0 时服务端兜底有效期

function ttlOf(creds) {
  return (creds && typeof creds.ttl === 'number' && TTL_OPTIONS.includes(creds.ttl)) ? creds.ttl : TTL_DEFAULT
}

// 密码强度：至少 8 位，必须包含小写、大写、数字和特殊符号
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
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
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

// ---------------- 会话管理（服务端内存） ----------------

const COOKIE_NAME = 'dsh_wua_session'

function sessionCookie(token, maxAgeSeconds) {
  let c = COOKIE_NAME + '=' + token + '; HttpOnly; SameSite=Lax; Path=/'
  if (maxAgeSeconds !== undefined) c += '; Max-Age=' + maxAgeSeconds
  return c
}

function clearSessionCookie() {
  return COOKIE_NAME + '=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'
}

// ---------------- 登录页（内联，不依赖 WebUI bundle） ----------------

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH WebUI 认证</title>
<style>
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
  button { width: 100%; margin-top: 18px; padding: 8px 18px; font-size: 13px; cursor: pointer;
    color: var(--dsw-alias-label-primary, #222); background: var(--dsw-alias-bg-layer-1, #fff);
    border: 1px solid var(--dsw-alias-border-l2, #999); border-radius: 4px; }
  button:disabled { opacity: .55; cursor: default; }
  .err { display: none; margin: 10px 0 0; font-size: 12px; color: var(--dsw-alias-state-error-primary, #d1242f); }
  .hint { margin: 14px 0 0; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888);
    border-top: 1px solid var(--dsw-alias-border-l1, #e5e5e5); padding-top: 10px; }
</style>
</head>
<body>
<div class="card">
  <h1>DSH WebUI</h1>
  <p class="sub" id="sub"></p>
  <form id="f">
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
  <p class="hint">忘记密码：删除插件目录的 dsh-webui-auth.json 文件即可重置。</p>
</div>
<script>
var MODE = "__MODE__";
var sub = document.getElementById('sub'), pl = document.getElementById('pl'),
  pc = document.getElementById('pc'), e = document.getElementById('e'),
  u = document.getElementById('u'), p = document.getElementById('p'),
  p2 = document.getElementById('p2'), b = document.getElementById('b'),
  f = document.getElementById('f');
function show(msg) { e.textContent = msg; e.style.display = 'block'; }
if (MODE === 'setup') {
  sub.textContent = '首次使用：创建管理员账号密码，之后访问 WebUI 需要登录。';
  pl.textContent = '密码（至少 8 位，含大小写、数字、特殊符号）';
  pc.style.display = 'block';
  b.textContent = '创建账号';
} else {
  sub.textContent = '此界面已启用身份认证，请登录后继续使用。';
}
f.addEventListener('submit', function (ev) {
  ev.preventDefault();
  var username = u.value.trim(), password = p.value;
  if (MODE === 'setup') {
    if (!username) return show('请输入用户名');
    if (password.length < 8) return show('密码至少需要 8 位');
    if (!/[a-z]/.test(password)) return show('密码必须包含小写字母');
    if (!/[A-Z]/.test(password)) return show('密码必须包含大写字母');
    if (!/[0-9]/.test(password)) return show('密码必须包含数字');
    if (!/[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/~]/.test(password)) return show('密码必须包含特殊符号');
    if (password !== p2.value) return show('两次输入的密码不一致');
  }
  b.disabled = true; b.textContent = '请稍候…';
  fetch(MODE === 'setup' ? '/dsh-webui-auth/setup' : '/dsh-webui-auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: username, password: password })
  }).then(function (r) { return r.json(); }).then(function (r) {
    if (r && r.ok) { location.href = '/'; return; }
    b.disabled = false; b.textContent = MODE === 'setup' ? '创建账号' : '登录';
    if (r && r.error === 'rate-limited') show('尝试次数过多，请一分钟后重试');
    else if (r && r.error === 'weak-password') show('密码强度不足：至少 8 位，需包含大小写字母、数字和特殊符号');
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

// ---------------- 核心包补丁自检与自动重打 ----------------
//
// /api 与 WebSocket 的会话闸门需要修改 DSH 核心包源码。升级 DSH（npx 拉取
// 新版本）会覆盖这些文件，导致闸门静默失效。插件启动时检测补丁标记
// `[dsh-webui-auth patch]`，缺失且锚点匹配则自动重新插入；锚点不匹配
// （核心包重构）则明确记录错误，不再静默失效。

export const CORE_PATCHES = [
  {
    pkg: '@deepseek-ai/dsh-client-connection',
    marker: '// [dsh-webui-auth patch] optional session gate — the persistent plugin',
    anchor: 'await bridge(req, res, fetchHandler, maxRequestBodyBytes);',
    insert: '\t\t\t// [dsh-webui-auth patch] optional session gate — the persistent plugin\n'
      + '\t\t\t// dsh-webui-auth plugin mounts webServer.webuiAuthGate when WebUI\n'
      + '\t\t\t// authentication is enabled; unauthorized callers get 401.\n'
      + '\t\t\tconst authGate = ctx.webServer["webuiAuthGate"];\n'
      + '\t\t\tif (authGate !== void 0 && !authGate.checkRequest(req)) {\n'
      + '\t\t\t\tres.writeHead(401);\n'
      + '\t\t\t\tres.end("unauthorized");\n'
      + '\t\t\t\treturn;\n'
      + '\t\t\t}\n'
      + '\t\t\t',
  },
  {
    pkg: '@deepseek-ai/dsh-client-connection',
    marker: '// [dsh-webui-auth patch] optional session gate — same hook as',
    anchor: 'return handle(req, socket, head);',
    insert: '\t\t\t\t\t// [dsh-webui-auth patch] optional session gate — same hook as\n'
      + '\t\t\t\t\t// the /api route; unauthorized WebSocket upgrades are rejected.\n'
      + '\t\t\t\t\tconst authGate = apiCtx.webServer["webuiAuthGate"];\n'
      + '\t\t\t\t\tif (authGate !== void 0 && !authGate.checkRequest(req)) {\n'
      + '\t\t\t\t\t\trejectWebSocketUpgrade(socket);\n'
      + '\t\t\t\t\t\treturn;\n'
      + '\t\t\t\t\t}\n'
      + '\t\t\t\t\t',
  },
  {
    pkg: '@deepseek-ai/dsh-client-modules',
    marker: '// [dsh-webui-auth patch] optional bundle gate — the persistent plugin',
    after: true, // serveBundle 是方法定义行：补丁须插入在其后的方法体内
    anchor: 'serveBundle = async (req, res) => {',
    insert: '\n\t\t// [dsh-webui-auth patch] optional bundle gate — the persistent plugin\n'
      + '\t\t// dsh-webui-auth plugin mounts webServer.webuiAuthGate when WebUI\n'
      + '\t\t// authentication is enabled; unauthenticated bundle requests redirect\n'
      + '\t\t// to the login page.\n'
      + '\t\tconst authGate = this.ctx.webServer["webuiAuthGate"];\n'
      + '\t\tif (authGate !== void 0 && !authGate.checkRequest(req)) {\n'
      + '\t\t\tres.writeHead(302, { location: "/dsh-webui-auth/login" });\n'
      + '\t\t\tres.end();\n'
      + '\t\t\treturn;\n'
      + '\t\t}\n'
      + '\t\t',
  },
]

/**
 * 对单个文件应用补丁。
 * @returns 'skip'（已带该补丁标记）| 'reapplied'（本次重新插入）| 'error'（失败）
 */
export function applyCorePatch(file, patch, logger) {
  let src
  try {
    src = readFileSync(file, 'utf8')
  } catch (e) {
    logger.error('[dsh-webui-auth] cannot read ' + file + ': ' + (e && e.message ? e.message : String(e)))
    return 'error'
  }
  if (src.indexOf(patch.marker) !== -1) return 'skip' // 该补丁已存在
  const at = src.indexOf(patch.anchor)
  if (at === -1) {
    logger.error('[dsh-webui-auth] PATCH ANCHOR NOT FOUND in ' + file + ' (' + patch.pkg + ') — /api and WebSocket are NOT protected! DSH may have upgraded; apply the patch manually.')
    return 'error'
  }
  if (src.indexOf(patch.anchor, at + patch.anchor.length) !== -1) {
    logger.error('[dsh-webui-auth] patch anchor not unique in ' + file + ' (' + patch.pkg + ') — refusing to patch automatically.')
    return 'error'
  }
  const insertAt = patch.after === true ? at + patch.anchor.length : at
  try {
    writeFileSync(file, src.slice(0, insertAt) + patch.insert + src.slice(insertAt))
  } catch (e) {
    logger.error('[dsh-webui-auth] cannot write patch to ' + file + ': ' + (e && e.message ? e.message : String(e)))
    return 'error'
  }
  logger.warn('[dsh-webui-auth] re-applied core patch to ' + file + ' — takes effect on next DSH start')
  return 'reapplied'
}

/**
 * 解析核心包入口文件并逐项应用补丁。
 * 报错双通道：宿主日志（控制台）输出 + 返回汇总供 WebUI 设置页展示。
 * @returns {{ ok: boolean, reapplied: boolean, problems: string[] }}
 */
export function ensureCorePatches(ctx) {
  const realLogger = ctx.logger || console
  const problems = []
  let reapplied = false
  const logger = {
    error(msg) {
      try { realLogger.error(msg) } catch (e) { /* ignore */ }
      problems.push(msg)
    },
    warn(msg) {
      try { realLogger.warn(msg) } catch (e) { /* ignore */ }
    },
    info(msg) {
      try { realLogger.info(msg) } catch (e) { /* ignore */ }
    },
  }
  let req
  try {
    req = createRequire(ctx.baseUrl)
  } catch (e) {
    logger.error('[dsh-webui-auth] cannot create module resolver; core patches not verified — /api and WebSocket may be unprotected.')
    return { ok: false, reapplied: false, problems }
  }
  for (const patch of CORE_PATCHES) {
    let file
    try {
      file = req.resolve(patch.pkg)
    } catch (e) {
      logger.error('[dsh-webui-auth] cannot resolve ' + patch.pkg + ' — /api and WebSocket are NOT protected.')
      continue
    }
    const result = applyCorePatch(file, patch, logger)
    if (result === 'reapplied') reapplied = true
  }
  return { ok: problems.length === 0, reapplied, problems }
}

export async function apply(ctx) {
  if (!selfTest()) {
    ctx.logger.error('[dsh-webui-auth] sha256 self-test FAILED — refusing to start')
    return
  }
  // 核心包补丁自检/自动重打（升级 DSH 后无需手动操作）
  const patchState = ensureCorePatches(ctx)
  if (!patchState.ok) {
    ctx.logger.error('[dsh-webui-auth] CORE PATCH PROBLEM — /api and WebSocket are NOT protected: ' + (patchState.problems[0] || 'unknown'))
  } else if (patchState.reapplied) {
    ctx.logger.warn('[dsh-webui-auth] core patches were re-applied — restart DSH once for full protection')
  }
  ctx.logger.info('[dsh-webui-auth] started, credentials file: ' + configPath())

  // 认证开关缓存：启动读取，configure/setup/disable 更新，60 秒后台刷新
  let enabledFlag = false
  async function refreshEnabled() {
    const creds = await readCredentials(ctx)
    enabledFlag = isEnabled(creds)
  }
  await refreshEnabled()

  // 服务端会话表 + 限流
  const sessions = new Map()
  let failures = []

  function checkRequest(req) {
    if (!enabledFlag) return true // 未启用认证：放行一切
    const token = cookieOf(req, COOKIE_NAME)
    if (!token) return false
    const s = sessions.get(token)
    if (!s) return false
    if (s.expiresAt <= Date.now()) {
      sessions.delete(token)
      return false
    }
    // 浏览器会话（ttl=0）：每次有效请求滑动续期，活跃则不过期；关闭浏览器后 cookie 消失
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
    for (const k of sessions.keys()) if (k !== keepToken) sessions.delete(k)
  }

  // 挂载会话闸门（dsh-client-connection 补丁读取；webServer 是共享实例，所有 ctx 可见）
  ctx.effect(() => {
    ctx.webServer['webuiAuthGate'] = { checkRequest }
    return () => {
      if (ctx.webServer['webuiAuthGate'] !== undefined) delete ctx.webServer['webuiAuthGate']
    }
  }, 'dsh-webui-auth: webuiAuthGate')

  // 后台任务：过期会话清理 + enabled 状态刷新
  const bgTimer = setInterval(async () => {
    const now = Date.now()
    for (const [k, s] of sessions) if (s.expiresAt <= now) sessions.delete(k)
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
          const page = LOGIN_PAGE.replace('__MODE__', enabledFlag ? 'login' : 'setup')
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
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
          const now = Date.now()
          failures = failures.filter((t) => now - t < 60000)
          if (failures.length >= 5) {
            sendJson(res, 200, { ok: false, error: 'rate-limited' })
            return
          }
          if (username === creds.username && hashPassword(creds.salt, password) === creds.hash) {
            const s = createSession(username, ttlOf(creds))
            res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
            sendJson(res, 200, { ok: true })
            return
          }
          failures.push(now)
          sendJson(res, 200, { ok: false, error: 'invalid' })
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
          sendJson(res, 200, { ok: false, error: 'already-configured' })
          return
        }
        const body = await readJsonBody(req, res)
        if (body === null) return
        const username = String(body.username || '').trim()
        const password = String(body.password || '')
        if (!username) {
          sendJson(res, 200, { ok: false, error: 'username-empty' })
          return
        }
        const st = passwordStrength(password)
        if (!st.ok) {
          sendJson(res, 200, { ok: false, error: 'weak-password', reason: st.reason })
          return
        }
        const salt = randomSalt()
        await writeCredentials(ctx, { v: 1, username, salt, hash: hashPassword(salt, password), ttl: TTL_DEFAULT })
        enabledFlag = true
        failures = []
        const s = createSession(username, TTL_DEFAULT)
        res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
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
        destroySession(req)
        res.setHeader('Set-Cookie', clearSessionCookie())
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
          patch: { ok: patchState.ok, reapplied: patchState.reapplied, problem: patchState.problems[0] || '' },
        })
      } catch (e) {
        sendJson(res, 500, { error: e && e.message ? e.message : String(e) })
      }
    },
  }), 'dsh-webui-auth: status')

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
        if (!username) {
          sendJson(res, 200, { ok: false, error: 'username-empty' })
          return
        }
        const wasEnabled = isEnabled(creds)
        const keepPassword = wasEnabled && !password
        if (!keepPassword) {
          const st = passwordStrength(password)
          if (!st.ok) {
            sendJson(res, 200, { ok: false, error: 'weak-password', reason: st.reason })
            return
          }
        }
        if (wasEnabled) {
          if (!current || hashPassword(creds.salt, current) !== creds.hash) {
            sendJson(res, 200, { ok: false, error: 'current-invalid' })
            return
          }
        }
        let ttl = wasEnabled ? ttlOf(creds) : TTL_DEFAULT
        if (body.ttl !== undefined) {
          ttl = Number(body.ttl)
          if (!Number.isInteger(ttl) || !TTL_OPTIONS.includes(ttl)) {
            sendJson(res, 200, { ok: false, error: 'ttl-invalid' })
            return
          }
        }
        let salt
        let hash
        if (keepPassword) {
          salt = creds.salt
          hash = creds.hash
        } else {
          salt = randomSalt()
          hash = hashPassword(salt, password)
        }
        await writeCredentials(ctx, { v: 1, username, salt, hash, ttl })
        enabledFlag = true
        failures = []
        if (wasEnabled) {
          // 修改凭据：吊销除当前会话外的所有会话
          const keepToken = cookieOf(req, COOKIE_NAME)
          destroyAllSessionsExcept(keepToken)
        } else {
          // 首次启用：直接建立会话
          const s = createSession(username, ttl)
          res.setHeader('Set-Cookie', sessionCookie(s.token, s.maxAge))
        }
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
        if (!isEnabled(creds)) {
          sendJson(res, 200, { ok: true })
          return
        }
        if (!current || hashPassword(creds.salt, current) !== creds.hash) {
          sendJson(res, 200, { ok: false, error: 'current-invalid' })
          return
        }
        await writeCredentials(ctx, { v: 1, enabled: false })
        sessions.clear()
        res.setHeader('Set-Cookie', clearSessionCookie())
        enabledFlag = false
        failures = []
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
