/**
 * issue #9 回归：核心兜底席位（webServer.fallback）的形态适配。
 *
 * 真实故障链（DSH 核心 0.2.2-rc.1 + dsh-webui-auth 0.3.6）：
 *   · dsh-host-frontend-static 用 `registerFallback({ resource })` 占住兜底席位，
 *     所以 `ctx.webServer.fallback` 是**对象**，不是函数；
 *   · 插件拿 `fallback !== undefined` 当"可调用"判断，直接 `await fallback(req, res)`
 *     → TypeError: fallback is not a function → 外层 catch 折成 500；
 *   · 现象是 token→cookie 交换 500，浏览器被弹回登录页（白屏/卡死）。
 *
 * 这里同时喂两种真实形态：
 *   handler  —— 旧核心的 registerFallback(handler)，fallback 本身可调用；
 *   resource —— 0.2.2-rc.1+ 的 registerFallback({ resource })，必须走 serveResource；
 *   unknown  —— 认不出的形态，必须回 404 + 一次性「不兼容」诊断，绝不抛 500。
 *
 * 运行：node test/fallback-shape.test.mjs
 */
import { mkdtempSync, copyFileSync, cpSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'

let pass = 0
let fail = 0
function eq(name, got, want) {
  if (got === want) {
    pass++
    console.log('  ok   ' + name + '  -> ' + JSON.stringify(got))
  } else {
    fail++
    console.log('  FAIL ' + name + '  got ' + JSON.stringify(got) + ' want ' + JSON.stringify(want))
  }
}

const here = dirname(fileURLToPath(import.meta.url))
const pluginRoot = join(here, '..')
const SESSION_TOKEN = 'plugin-session-token'
const CORE_COOKIE = 'dsh-auth-corehash=corecookie'
const CORE_TOKEN = 'core-launch-token'
const LOOPBACK = '127.0.0.1'

/** 核心兜底席位的真实行为：GET / 出 index，GET /?token= 做 303 交换，其余 401。 */
function coreRespond(req, res) {
  const url = new URL(req.url || '/', 'http://x')
  if (url.pathname === '/' && url.searchParams.get('token') === CORE_TOKEN) {
    res.writeHead(303, { location: './', 'cache-control': 'no-store', 'set-cookie': CORE_COOKIE + '; Path=/; HttpOnly' })
    res.end()
    return
  }
  if (url.pathname === '/' && String(req.headers.cookie || '').includes('dsh-auth-corehash=')) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<!doctype html>INDEX')
    return
  }
  res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
  res.end('dsh web authentication required')
}

/** 复刻 dsh-host-frontend-static 的 resource：请求 → Response。 */
function coreResource(request) {
  const url = new URL(request.url)
  if (url.pathname === '/' && url.searchParams.get('token') === CORE_TOKEN) {
    return new Response(null, { status: 303, headers: { location: './', 'cache-control': 'no-store', 'set-cookie': CORE_COOKIE + '; Path=/; HttpOnly' } })
  }
  if (url.pathname === '/' && String(request.headers.get('cookie') || '').includes('dsh-auth-corehash=')) {
    return new Response('<!doctype html>INDEX', { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } })
  }
  return new Response('dsh web authentication required', { status: 401, headers: { 'content-type': 'text/plain; charset=utf-8' } })
}

async function makeHarness(shape) {
  const sandbox = mkdtempSync(join(tmpdir(), 'dsh-wua-9-' + shape + '-'))
  copyFileSync(join(pluginRoot, 'index.js'), join(sandbox, 'index.js'))
  cpSync(join(pluginRoot, 'lib'), join(sandbox, 'lib'), { recursive: true })
  writeFileSync(join(sandbox, 'dsh-webui-auth.json'), JSON.stringify({
    v: 3, username: 'tester', hash: 'scrypt:32768:8:1:AAAA:BBBB', ttl: 72,
  }))
  writeFileSync(join(sandbox, 'sessions.jsonl'),
    JSON.stringify({ op: 'add', token: SESSION_TOKEN, sess: { username: 'tester', expiresAt: Date.now() + 3600_000, browser: false } }) + '\n')

  const mod = await import(pathToFileURL(join(sandbox, 'index.js')).href)
  const logs = []
  const reg = { routes: [], resourceCalls: 0, serveCalls: 0 }

  const webServer = {
    port: 3080,
    exact: new Map(),
    prefixes: new Map(),
    upgrades: new Map(),
    register(route) {
      reg.routes.push(route)
      if (route.kind === 'exact' && route.path !== undefined) this.exact.set(route.path, route)
      else this.prefixes.set(route.path, route)
      return () => {}
    },
  }

  if (shape === 'handler') {
    webServer.fallback = (req, res) => { reg.serveCalls++; return Promise.resolve(coreRespond(req, res)) }
  } else if (shape === 'resource') {
    // 0.2.2-rc.1 的形状：席位是 { resource }，且核心暴露 serveResource()
    webServer.fallback = { resource: async (request) => { reg.resourceCalls++; return coreResource(request) } }
    webServer.serveResource = async (req, res, target, resource) => {
      reg.serveCalls++
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD' })
        res.end()
        return
      }
      const headers = new Headers()
      for (const [name, value] of Object.entries(req.headers || {})) headers.append(name, String(value))
      const response = await resource(new Request(target, { method: req.method, headers }))
      const out = {}
      response.headers.forEach((value, key) => { out[key] = value })
      res.writeHead(response.status, out)
      res.end(await response.text())
    }
  } else {
    webServer.fallback = { unexpected: true }
  }

  const connection = {
    requestRejection(req) {
      return String((req.headers && req.headers.cookie) || '').includes('dsh-auth-corehash=') ? undefined : 401
    },
    authenticatedUrl(base) {
      const url = new URL(base)
      url.searchParams.set('token', CORE_TOKEN)
      return url.href
    },
  }

  const ctx = {
    fs: {
      async resolve(p) { return p },
      async readText(p) { try { return readFileSync(p, 'utf8') } catch (e) { return null } },
      async writeText() {},
    },
    effect(fn) { const d = fn(); return () => { if (typeof d === 'function') d() } },
    logger: {
      info: (m) => logs.push(['info', String(m)]),
      warn: (m) => logs.push(['warn', String(m)]),
      error: (m) => logs.push(['error', String(m)]),
    },
    webServer,
    get(ns) {
      if (ns === 'webServer') return webServer
      if (ns === 'connection') return connection
      if (ns === 'settings') return { get: () => undefined }
      return undefined
    },
  }

  await mod.apply(ctx)

  const gate = reg.routes.find((r) => r.kind === 'prefix' && r.path === '')
  if (!gate) throw new Error('prefix "" transport gate not registered')
  const statusRoute = reg.routes.find((r) => r.kind === 'exact' && r.path === '/dsh-webui-auth/status')

  function makeRes(out) {
    return {
      on() { return this },
      off() { return this },
      get headersSent() { return out.headersSent },
      setHeader(k, v) { out.headers[k.toLowerCase()] = v },
      writeHead(status, extra) {
        out.status = status
        if (extra) for (const k of Object.keys(extra)) out.headers[k.toLowerCase()] = String(extra[k])
        out.headersSent = true
      },
      end(body) { if (body !== undefined) out.body = String(body) },
      destroy() {},
    }
  }

  async function call(handler, { url = '/', method = 'GET', cookie = null, remote = LOOPBACK } = {}) {
    const out = { status: 0, headers: {}, body: '', headersSent: false }
    const headers = { host: '127.0.0.1:3080' }
    if (cookie !== null) headers.cookie = cookie
    const req = { url, method, headers, socket: { remoteAddress: remote } }
    await handler(req, makeRes(out))
    return out
  }

  return { sandbox, logs, reg, gate, statusRoute, call }
}

/** 一次完整断言流程：文档请求 + token 交换都必须交给核心。 */
async function checkShape(shape) {
  const h = await makeHarness(shape)
  try {
    console.log('\n— 形态：' + shape + ' —')
    const doc = await h.call(h.gate.handler, { url: '/', cookie: 'dsh_wua_session=' + SESSION_TOKEN + '; ' + CORE_COOKIE })
    eq('已登录文档请求由核心回 200（不再 500）', doc.status, 200)
    eq('返回的是核心 index.html', doc.body.includes('INDEX'), true)
    eq('兜底席位确实被调用', h.reg.serveCalls >= 1, true)

    const exchange = await h.call(h.gate.handler, { url: '/?token=' + CORE_TOKEN })
    eq('token→cookie 交换由核心回 303', exchange.status, 303)
    eq('303 携带核心 set-cookie', String(exchange.headers['set-cookie'] || '').startsWith('dsh-auth-corehash='), true)

    const status = await h.call(h.statusRoute.handler, { url: '/dsh-webui-auth/status', cookie: CORE_COOKIE })
    eq('status 端点报出兜底席位形态', JSON.parse(status.body).fallback, shape)
    eq('没有 TypeError 被折成 500', h.logs.some(([lvl, m]) => lvl === 'warn' && m.includes('intercept error')), false)
    return h
  } finally {
    try { rmSync(h.sandbox, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
}

try {
  await checkShape('handler')
  await checkShape('resource')

  console.log('\n— 形态：unknown（核心又变了）—')
  const unknown = await makeHarness('unknown')
  try {
    const doc = await unknown.call(unknown.gate.handler, { url: '/', cookie: 'dsh_wua_session=' + SESSION_TOKEN + '; ' + CORE_COOKIE })
    eq('未知形态回 404（不是 500）', doc.status, 404)
    eq('404 写明是 fallback 形态问题', doc.body.includes('webServer.fallback'), true)
    eq('以 error 级别报告不兼容核心', unknown.logs.some(([lvl, m]) => lvl === 'error' && m.includes('INCOMPATIBLE CORE')), true)
    eq('没有 TypeError 被折成 500', unknown.logs.some(([lvl, m]) => lvl === 'warn' && m.includes('intercept error')), false)

    const exchange = await unknown.call(unknown.gate.handler, { url: '/?token=' + CORE_TOKEN })
    eq('token 交换同样回 404（不再 302 到登录页死循环）', exchange.status, 404)
    eq('启动自检已报出 unknown 形态', unknown.logs.some(([lvl, m]) => lvl === 'error' && m.includes('INCOMPATIBLE CORE')), true)
  } finally {
    try { rmSync(unknown.sandbox, { recursive: true, force: true }) } catch (e) { /* ignore */ }
  }
} finally {
  /* 插件的后台定时器会吊住事件循环；测试结束直接退出。 */
}

console.log('\n' + pass + ' passed, ' + fail + ' failed')
process.exit(fail === 0 ? 0 : 1)
