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
 * Password hashing: scrypt (Node built-in memory-hard KDF). Credentials written
 * by older builds (v1 salted SHA-256) are no longer verifiable — delete
 * dsh-webui-auth.json and recreate the account to upgrade (see README).
 *
 * Audit log: security events (login success/failure/rate-limit, setup,
 * configure, disable, logout) are appended as JSONL to audit.jsonl in the
 * plugin folder. View via CLI:  node index.js audit [--limit N]
 *
 * Credentials live in the plugin's own folder (`dsh-webui-auth.json` next to
 * this module) when that folder is writable (link/source installs); when the
 * module folder is read-only (npm/pnpm store installs) they fall back to
 * `$DSH_HOME/dsh-webui-auth/`. Stored as an scrypt hash — never plaintext.
 *
 * Endpoints:
 *   GET  /dsh-webui-auth/login       login page (public, mode by enabled state)
 *   POST /dsh-webui-auth/login       { username, password }   -> { ok, error? }
 *   POST /dsh-webui-auth/setup       { username, password }   -> { ok, error? } (first-run only)
 *   POST /dsh-webui-auth/logout      (session required)       -> { ok }
 *   GET  /dsh-webui-auth/status      (session required)       -> { enabled, username, ttl }
 *   GET  /dsh-webui-auth/audit       (session required)       -> { ok, entries: [...] } (?limit=N)
 *   POST /dsh-webui-auth/configure   (session required) { username, password?, current, ttl? }
 *   POST /dsh-webui-auth/disable     (session required) { current }
 */

import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, appendFileSync, accessSync, mkdirSync, constants as fsConstants } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve as resolvePath } from "node:path";
import { promisify } from "node:util";

export const name = 'dsh-webui-auth'

export const inject = ['webServer', 'fs', 'clientModules']

// ---------------- 密码哈希：scrypt（Node 内置内存硬 KDF，零依赖） ----------------
//
// 取代旧版手写 SHA-256：SHA-256 极快，GPU 上每秒可算数十亿次，加盐也无济于事；
// scrypt 是内存硬 KDF（计算需占用大量内存，难以并行/ASIC 加速），是 Node 官方
// 推荐的口令哈希方案（npm 自身认证体系即用它）。
//
// 存储格式（自描述，参数可随版本调整）：
//   "scrypt:N:r:p:saltB64:hashB64"
// 注意：旧版 v1 凭据（SHA-256）自 0.2.0 起不再支持校验，需删除
// dsh-webui-auth.json 后重新创建账号（见 README「忘记密码」）。

const SCRYPT_N = 32768          // 2^15，约 32 MiB 内存
const SCRYPT_R = 8
const SCRYPT_P = 1
const SCRYPT_KEYLEN = 64
const SCRYPT_MAXMEM = 64 * 1024 * 1024
const SCRYPT_PREFIX = 'scrypt:'

const scrypt = promisify(scryptCb)

/** 生成新密码哈希（含随机盐），格式见上。 */
async function hashPassword(password) {
  const salt = randomBytes(16).toString('base64')
  const derived = await scrypt(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM })
  return SCRYPT_PREFIX + SCRYPT_N + ':' + SCRYPT_R + ':' + SCRYPT_P + ':' + salt + ':' + derived.toString('base64')
}

/** 校验 scrypt 哈希（恒定时间比较）。格式异常一律返回 false，绝不抛错。 */
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

/**
 * 时序均衡：用户名不存在/哈希格式不符时，对固定 dummy 哈希做一次与真实
 * 校验等价的 scrypt 验证（结果恒为 false），使"账号不存在"与"密码错误"
 * 的响应耗时一致，抹平用户名枚举差异。
 */
let dummyHashPromise = null
function dummyHash() {
  if (dummyHashPromise === null) {
    dummyHashPromise = hashPassword(randomBytes(8).toString('hex')).catch((e) => {
      dummyHashPromise = null // 生成失败可重试，不永久卡死
      throw e
    })
  }
  return dummyHashPromise
}
async function dummyVerify(password) {
  const h = await dummyHash()
  return verifyPassword(password, h) // 恒 false，但成本与真实校验一致（恰好 1 次 scrypt）
}

// 供测试与工具脚本使用（Cordis 加载时只消费 name/inject/apply，多余导出无副作用）
export { hashPassword, verifyPassword, auditLog, readAuditEntries, resolveDataDirFrom, DATA_DIR }

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

/**
 * 运行时数据目录（凭据 + 审计日志）。
 *
 * 优先插件目录——link 安装/源码部署时可写，数据与模块同处一地（卸载即清、
 * 随仓库管理）；npm/pnpm store 安装时模块目录只读（store 文件不可写），
 * 写入会导致 500，此时回退到 $DSH_HOME/dsh-webui-auth/（DSH 自己的配置目录，
 * 保证可写）。启动时探测一次并缓存。
 */
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

/** 确保数据目录存在（回退目录首次写入前需要创建）。 */
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

// 用户名约束：3-32 位字母、数字、下划线或连字符。
// 登录/验证时不做格式校验（旧账号不受影响），仅在新建/修改凭据时强制。
const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/

function usernameError(username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return '用户名需为 3-32 位字母、数字、下划线或连字符'
  }
  return null
}

// ---------------- 审计日志（JSONL 追加写，与凭据同目录） ----------------
//
// 记录登录成功/失败/限流/锁定、初始化、修改、禁用、退出等安全事件。
// 追加写不阻塞主流程：失败仅记日志，绝不影响认证本身。
// 查看：node index.js audit [--limit N]（CLI 模式，见文件末尾）。

const AUDIT_FILE = 'audit.jsonl'

function auditFileForCli() {
  return DATA_DIR + '/' + AUDIT_FILE
}

async function auditFilePath(ctx) {
  try {
    // ctx.fs.resolve 返回 { targetKey, displayPath } 对象（不是字符串），
    // 原生 node:fs 需要物理路径 displayPath；targetKey 仅供 ctx.fs 自身使用。
    const r = await ctx.fs.resolve(DATA_DIR + '/' + AUDIT_FILE)
    if (r && typeof r.displayPath === 'string') return r.displayPath
    if (r && typeof r.targetKey === 'string') return r.targetKey
  } catch (e) { /* fall through */ }
  return DATA_DIR + '/' + AUDIT_FILE
}

/**
 * 追加一条审计事件。fields 中的值必须是字符串/数字/null。
 */
async function auditLog(ctx, event, fields) {
  let target = null
  try {
    target = await auditFilePath(ctx)
    if (!target) return
    ensureDataDir()
    const entry = { ts: new Date().toISOString(), event }
    for (const key of Object.keys(fields || {})) {
      const v = fields[key]
      if (v === undefined) continue
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
  let ua = null
  try { ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null } catch (e) { /* ignore */ }
  return { ip, ua }
}

/**
 * 读取最近 limit 条审计记录（新→旧）。文件缺失/损坏时返回空数组，绝不抛错。
 */
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

// ---------------- DSH 外观偏好（浅色 / 深色 / 跟随系统） ----------------
//
// 复用 DSH 自带的外观设置：settings 命名空间 `ui-theme` 的 preference 字段
// （与 @deepseek-ai/dsh-client-ui-theme 的 THEME_SETTINGS_NAMESPACE /
// DEFAULT_PREFERENCE 完全一致），不新增独立外观开关。登录页是独立页面，
// 加载不到 WebUI 的主题样式表，因此由服务端把当前偏好注入页面
// （__THEME_PREFERENCE__），页面内嵌 design-platform 别名 token 子集并
// 复刻 DSH 的 bootThemeScript：light → 浅色；dark → 深色；system → 按
// prefers-color-scheme 实时跟随系统。
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

// ---------------- 登录页（内联，不依赖 WebUI bundle） ----------------

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>DSH WebUI 认证</title>
<style>
  /* DSH design-platform 别名 token 子集（逐项镜像 @deepseek-ai/dsh-client-ui-theme
     lib/styles/design-platform.css）。登录页独立于 WebUI，无法加载其主题样式表，
     故内嵌本页用到的 token：浅色定义在 body，深色定义在 body[data-ds-dark-theme]，
     切换机制与 WebUI 完全一致（属性由下方 boot 脚本按 DSH 外观偏好设置）。 */
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
    --dsw-alias-state-success-primary: rgb(34, 197, 94);
    --dsw-alias-state-warn-primary: rgb(245, 158, 11);
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
    --dsw-alias-state-success-primary: rgb(34, 197, 94);
    --dsw-alias-state-warn-primary: rgb(245, 158, 11);
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
  /* 深色模式下浏览器自动填充会把输入框刷成白色/黄色：用 inset 大阴影 + text-fill-color
     回压为当前主题的输入底色（与 DSH 主题 token 联动，明暗模式都正确） */
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
</style>
</head>
<body>
<script>
/* DSH 外观偏好（服务端注入：light / dark / system）。
   与 WebUI 的 bootThemeScript 同一逻辑：system 时按系统 prefers-color-scheme
   解析并实时响应系统切换；结果以 body 上的 data-ds-dark-theme 驱动上面的
   token 选择器，与 DSH 内置外观设置保持一致。 */
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
function validUsername(name) { return /^[A-Za-z0-9_-]{3,32}$/.test(name); }
f.addEventListener('submit', function (ev) {
  ev.preventDefault();
  var username = u.value.trim(), password = p.value;
  if (MODE === 'setup') {
    if (!validUsername(username)) return show('用户名需为 3-32 位字母、数字、下划线或连字符');
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
          const page = LOGIN_PAGE
            .replace('__MODE__', enabledFlag ? 'login' : 'setup')
            .replace('__THEME_PREFERENCE__', themePreference(ctx))
          // 登录页安全响应头：页面完全自包含（内联 CSS/JS、无外部资源），可上严格 CSP
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
          const now = Date.now()
          failures = failures.filter((t) => now - t < 60000)
          if (failures.length >= 5) {
            await auditLog(ctx, 'login_rate_limited', { username: username || null, ip: meta.ip, ua: meta.ua })
            sendJson(res, 200, { ok: false, error: 'rate-limited' })
            return
          }
          // 凭据校验：仅接受 scrypt 哈希（v1 SHA-256 自 0.2.0 起不再支持，
          // 旧凭据需删除 dsh-webui-auth.json 后重新创建）。
          // 登录不做用户名格式校验，旧账号不受新规则影响。
          // 三种情况耗时一致（恰好 1 次 scrypt）：正确 / 密码错误 / 用户名不存在。
          let valid = false
          if (username === creds.username && typeof creds.hash === 'string') {
            valid = await verifyPassword(password, creds.hash)
          } else {
            valid = await dummyVerify(password)
          }
          if (!valid) {
            failures.push(now)
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
        const body = await readJsonBody(req, res)
        if (body === null) return
        const username = String(body.username || '').trim()
        const password = String(body.password || '')
        const meta = requestMeta(req)
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
        await writeCredentials(ctx, { v: 2, username, hash: await hashPassword(password), ttl: TTL_DEFAULT })
        enabledFlag = true
        failures = []
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
          patch: { ok: patchState.ok, reapplied: patchState.reapplied, problem: patchState.problems[0] || '' },
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
        // 仅当现有哈希是 scrypt 格式时才允许"密码留空=不修改"：
        // 旧版 v1 哈希（非 scrypt）不能被原样保留（登录校验只认 scrypt），
        // 此时必须提供新密码，否则账号会因哈希格式不符而无法登录。
        const hashIsScrypt = typeof creds.hash === 'string' && creds.hash.startsWith(SCRYPT_PREFIX)
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
        let ttl = wasEnabled ? ttlOf(creds) : TTL_DEFAULT
        if (body.ttl !== undefined) {
          ttl = Number(body.ttl)
          if (!Number.isInteger(ttl) || !TTL_OPTIONS.includes(ttl)) {
            sendJson(res, 200, { ok: false, error: 'ttl-invalid' })
            return
          }
        }
        const credsOut = (keepPassword && typeof creds.hash === 'string')
          ? { v: 2, username, hash: creds.hash, ttl }
          : { v: 2, username, hash: await hashPassword(password), ttl }
        await writeCredentials(ctx, credsOut)
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
        failures = []
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
//
// 直接运行本文件时进入 CLI 模式（作为 Cordis 插件被 DSH 加载时不会触发，
// 此时 process.argv[1] 是 DSH 入口而非本文件）。审计日志为 JSONL 追加写，
// 位于插件目录 audit.jsonl（与凭据文件同目录）。
//
// 用法：
//   node index.js audit             查看最近 20 条审计日志
//   node index.js audit --limit 50  指定条数（1-200）

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
    // Windows 文件系统大小写不敏感：统一小写后再比较，避免
    // import.meta.url 与 argv[1] 的大小写差异导致 CLI 不触发
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
      if (r.ua) parts.push('ua=' + (typeof r.ua === 'string' && r.ua.length > 60 ? r.ua.slice(0, 60) + '…' : String(r.ua)))
      if (r.detail) parts.push('detail=' + String(r.detail))
      console.log('  ' + parts.join('  '))
    }
  } else {
    console.log('[dsh-webui-auth] 用法: node index.js audit [--limit N]')
  }
  process.exit(0)
}
