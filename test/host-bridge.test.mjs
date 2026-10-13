/**
 * #9 端到端回归：DSH Desktop 宿主直连信任桥（0.3.6）。
 *
 * 复现的是真实故障链：
 *   ① 桌面端 shell 启动握手 —— fetch(ready.url, {redirect:"manual"}) 要求宿主回
 *      303 + set-cookie（app.asar lib/main.js 的 authenticateWebHost），插件文档闸门
 *      原先回 302 → "Desktop Host authentication failed" → 桌面端启动失败；
 *   ② 桌面端渲染器请求 —— shell 的 forwardWebRequest 只带核心 Cookie（它把响应的
 *      set-cookie 丢弃，插件会话 Cookie 永远落不了地）→ /api、/plugins、WebSocket
 *      原先全 401 → 设置页整片打不开。
 *
 * 这里驱动的是 **apply() 真正注册的处理器**（prefix "" 传输层闸门 + 运行时路由闸门），
 * 而不是测试里复刻的一份决策逻辑，因此实现漂移会立刻把测试打红。
 *
 * index.js 在模块加载时把 DATA_DIR 定死在自己的目录下（MODULE_DIR），所以先把插件复制到
 * 临时目录再 import：凭据 / 会话 / 审计全部落在临时目录里，绝不触碰仓库中的真实数据。
 *
 * 运行：node test/host-bridge.test.mjs
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
const sandbox = mkdtempSync(join(tmpdir(), 'dsh-webui-auth-9-'))

const SESSION_TOKEN = 'plugin-session-token'
const CORE_COOKIE = 'dsh-auth-corehash=corecookie'
const CORE_TOKEN = 'core-launch-token'
const LOOPBACK = '127.0.0.1'
const REMOTE = '192.168.1.50'

try {
  copyFileSync(join(pluginRoot, 'index.js'), join(sandbox, 'index.js'))
  cpSync(join(pluginRoot, 'lib'), join(sandbox, 'lib'), { recursive: true })
  writeFileSync(join(sandbox, 'dsh-webui-auth.json'), JSON.stringify({
    v: 3, username: 'tester', hash: 'scrypt:32768:8:1:AAAA:BBBB', ttl: 72,
  }))
  writeFileSync(join(sandbox, 'sessions.jsonl'),
    JSON.stringify({ op: 'add', token: SESSION_TOKEN, sess: { username: 'tester', expiresAt: Date.now() + 3600_000, browser: false } }) + '\n')

  const mod = await import(pathToFileURL(join(sandbox, 'index.js')).href)

  // ---- 伪造 ctx：核心路由表 + 核心 BrowserAuth 语义 + connection ----
  const eventsOriginalHandler = (req, res) => { reg.eventsCalls++; res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end('data: {"type":"graph"}\n\n') }
  const reg = { pluginRoutes: [], apiCalls: 0, pluginCalls: 0, upgrades: 0, tokenExchanges: 0, eventsCalls: 0 }
  const logs = []

  const webServer = {
    port: 3080,
    // 运行时路由闸门会包装这两个"核心已注册"的前缀路由与 upgrade 路由
    prefixes: new Map([
      ['/api', { kind: 'prefix', path: '/api', handler: (req, res) => { reg.apiCalls++; res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}') } }],
      ['/plugins', { kind: 'prefix', path: '/plugins', handler: (req, res) => { reg.pluginCalls++; res.writeHead(200, { 'content-type': 'text/javascript' }); res.end('//bundle') } }],
    ]),
    upgrades: new Map([
      ['/api/remote.mux', { path: '/api/remote.mux', handler: (req, socket) => { reg.upgrades++; socket.write('HTTP/1.1 101 Switching Protocols\r\n\r\n') } }],
    ]),
    // 顶层 exact 路由：路由表对 exact 的优先级高于 prefix（client-hmr 的 /plugins/events 就是这一类）
    exact: new Map([
      ['/plugins/events', { kind: 'exact', path: '/plugins/events', handler: eventsOriginalHandler }],
    ]),
    // 模拟核心 frontend-static → connection.authorizeIndex
    async fallback(req, res) {
      const url = new URL(req.url, 'http://dsh.invalid')
      if (url.pathname === '/' && url.searchParams.getAll('token').length === 1 && url.searchParams.get('token') === CORE_TOKEN) {
        reg.tokenExchanges++
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
    },
    register(route) {
      reg.pluginRoutes.push(route)
      // 真实 webServer.register 会把 exact 路由放进 ws.exact（运行时闸门的 exact 扫描要看得到它们）
      if (route.kind === 'exact' && route.path !== undefined) webServer.exact.set(route.path, route)
      return () => {}
    },
  }

  // 核心公开契约：信任栅栏 + 浏览器会话校验（这里用核心 Cookie 代表"已被核心认证"）
  const connection = {
    requestRejection(req) {
      return String(req.headers.cookie || '').includes('dsh-auth-corehash=') ? undefined : 401
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
    logger: { info: (m) => logs.push(['info', m]), warn: (m) => logs.push(['warn', m]), error: (m) => logs.push(['error', m]) },
    webServer,
    get(ns) {
      if (ns === 'webServer') return webServer
      if (ns === 'connection') return connection
      if (ns === 'settings') return { get: () => undefined }
      return undefined
    },
  }

  await mod.apply(ctx)

  const documentGate = reg.pluginRoutes.find((r) => r.kind === 'prefix' && r.path === '')
  const apiGate = webServer.prefixes.get('/api')
  const pluginsGate = webServer.prefixes.get('/plugins')
  const upgradeGate = webServer.upgrades.get('/api/remote.mux')
  const eventsGate = webServer.exact.get('/plugins/events')
  const eventsOriginal = eventsOriginalHandler
  const statusRoute = reg.pluginRoutes.find((r) => r.kind === 'exact' && r.path === '/dsh-webui-auth/status')

  eq('apply() 注册了 prefix "" 传输层闸门', documentGate !== undefined, true)
  eq('运行时闸门包了 /api 路由', typeof apiGate.handler === 'function', true)
  eq('运行时闸门包了 /api/remote.mux upgrade', typeof upgradeGate.handler === 'function', true)
  eq('运行时闸门包了同前缀的顶层 exact 路由 /plugins/events', eventsGate.handler !== eventsOriginal, true)
  eq('插件自身端点未被误包装（handler 保持原对象）',
    webServer.exact.get('/dsh-webui-auth/status').handler === statusRoute.handler, true)
  eq('启动日志说明宿主桥已激活',
    logs.some(([lvl, m]) => lvl === 'info' && String(m).includes('host carrier bridge active')), true)

  // ---- 请求往返工具 ----
  function makeRes(out) {
    return {
      get headersSent() { return out.headersSent },
      setHeader(k, v) { out.headers[k.toLowerCase()] = v },
      writeHead(status, extra) {
        out.status = status
        if (extra) for (const k of Object.keys(extra)) out.headers[k.toLowerCase()] = extra[k]
        out.headersSent = true
      },
      end(body) {
        if (body !== undefined) out.body = String(body)
      },
      destroy() {},
    }
  }

  async function call(handler, { url = '/', method = 'GET', cookie = null, remote = LOOPBACK, socket = null, body = undefined } = {}) {
    const out = { status: 0, headers: {}, body: '', headersSent: false }
    const headers = { host: '127.0.0.1:3080' }
    if (cookie !== null) headers.cookie = cookie
    const req = {
      url,
      method,
      headers,
      socket: { remoteAddress: remote },
      // readJsonBody 走的是 req 的流接口，这里给一个最小实现
      on(event, cb) {
        if (body === undefined) return this
        if (event === 'data') setTimeout(() => cb(Buffer.from(body)), 0)
        else if (event === 'end') setTimeout(() => cb(), 1)
        return this
      },
    }
    if (socket === null) {
      await handler(req, makeRes(out))
    } else {
      await handler(req, socket, Buffer.alloc(0))
    }
    return { status: out.status, location: out.headers.location || null, body: out.body, setCookie: out.headers['set-cookie'] || null }
  }

  /** 解析 JSON 响应体（失败返回 null）。 */
  function json(result) {
    try { return JSON.parse(result.body) } catch (e) { return null }
  }

  console.log('\n— 场景一：桌面端 shell 启动握手（authenticateWebHost，本次崩溃点）—')
  reg.tokenExchanges = 0
  const hs = await call(documentGate.handler, { url: '/?token=' + CORE_TOKEN, remote: LOOPBACK })
  eq('核心 token 交换被交给核心（不是插件的登录跳转）', reg.tokenExchanges, 1)
  eq('桌面端拿到 303（authenticateWebHost 的硬性要求）', hs.status, 303)
  eq('303 携带核心 set-cookie', hs.setCookie !== null && hs.setCookie.startsWith('dsh-auth-corehash='), true)
  eq('重定向到干净的 ./', hs.location, './')

  console.log('\n— 场景二：桌面端渲染器转发请求（只带核心 Cookie，无插件会话）—')
  const api = await call(apiGate.handler, { url: '/api/settings/describe', method: 'POST', cookie: CORE_COOKIE, remote: LOOPBACK })
  eq('/api 放行到核心（不再 401）', api.status, 200)
  eq('/api 确实到达核心 handler', reg.apiCalls, 1)
  const bundle = await call(pluginsGate.handler, { url: '/plugins/dsh-webui-auth/client.js', cookie: CORE_COOKIE, remote: LOOPBACK })
  eq('/plugins 放行（设置页等客户端插件能加载）', bundle.status, 200)
  eq('/plugins 确实到达核心 handler', reg.pluginCalls, 1)

  let upgraded = null
  const wsSocket = { write(chunk) { upgraded = String(chunk) }, destroy() {} }
  await call(upgradeGate.handler, { url: '/api/remote.mux', cookie: CORE_COOKIE, remote: LOOPBACK, socket: wsSocket })
  eq('WebSocket 升级放行（事件流不再被 401 掐断）', reg.upgrades, 1)
  eq('升级写出 101', upgraded !== null && upgraded.includes('101'), true)

  const eventsOk = await call(eventsGate.handler, { url: '/plugins/events', cookie: CORE_COOKIE, remote: LOOPBACK })
  eq('宿主直连可读 /plugins/events（客户端 HMR 不断线）', eventsOk.status, 200)
  eq('/plugins/events 确实到达核心 handler', reg.eventsCalls, 1)

  console.log('\n— 场景三：网页版登录闸门零回归 —')
  const noCookie = await call(apiGate.handler, { url: '/api/settings/describe', method: 'POST', remote: LOOPBACK })
  eq('无凭据 /api 仍 401', noCookie.status, 401)
  const anonEvents = await call(eventsGate.handler, { url: '/plugins/events', remote: LOOPBACK })
  eq('匿名 /plugins/events 被闸门拦下（exact 路由旁路已堵）', anonEvents.status, 401)
  eq('匿名 /plugins/events 没有到达核心 handler', reg.eventsCalls, 1)
  const noCookieDoc = await call(documentGate.handler, { url: '/', remote: LOOPBACK })
  eq('无凭据文档请求仍跳登录页', noCookieDoc.location, '/dsh-webui-auth/login')
  const badToken = await call(documentGate.handler, { url: '/?token=wrong-token', remote: LOOPBACK })
  eq('token 不匹配时不放行', badToken.location, '/dsh-webui-auth/login')
  const multiToken = await call(documentGate.handler, { url: '/?token=' + CORE_TOKEN + '&token=' + CORE_TOKEN, remote: LOOPBACK })
  eq('重复 token 参数不放行（与核心 authorizeIndex 同规则）', multiToken.location, '/dsh-webui-auth/login')
  const withSession = await call(apiGate.handler, { url: '/api/x', cookie: 'dsh_wua_session=' + SESSION_TOKEN, remote: REMOTE })
  eq('插件会话依旧通行（含远端）', withSession.status, 200)

  console.log('\n— 场景四：豁免只对回环生效 —')
  const remoteApi = await call(apiGate.handler, { url: '/api/x', cookie: CORE_COOKIE, remote: REMOTE })
  eq('远端持有核心 Cookie 也不放行 /api', remoteApi.status, 401)
  const remoteDoc = await call(documentGate.handler, { url: '/?token=' + CORE_TOKEN, remote: REMOTE })
  eq('远端拿正确 token 也不放行文档交换（必须走口令）', remoteDoc.location, '/dsh-webui-auth/login')
  eq('远端请求没有触发核心交换', reg.tokenExchanges, 1)
  let remoteUpgrade = null
  await call(upgradeGate.handler, {
    url: '/api/remote.mux', cookie: CORE_COOKIE, remote: REMOTE,
    socket: { write(chunk) { remoteUpgrade = String(chunk) }, destroy() {} },
  })
  eq('远端 WebSocket 升级被拒（401）', remoteUpgrade !== null && remoteUpgrade.includes('401'), true)
  eq('远端升级没有到达核心', reg.upgrades, 1)

  console.log('\n— 场景五：插件自身端点（设置页读取 / 修改）—')
  const hostStatus = await call(statusRoute.handler, { url: '/dsh-webui-auth/status', cookie: CORE_COOKIE, remote: LOOPBACK })
  eq('桌面端能读状态', hostStatus.status, 200)
  eq('状态里标出 carrier=host', hostStatus.body.includes('"carrier":"host"'), true)
  const remoteStatus = await call(statusRoute.handler, { url: '/dsh-webui-auth/status', remote: REMOTE })
  eq('远端未登录读状态仍 401', remoteStatus.status, 401)
  const sessionStatus = await call(statusRoute.handler, { url: '/dsh-webui-auth/status', cookie: 'dsh_wua_session=' + SESSION_TOKEN, remote: REMOTE })
  eq('浏览器会话读到 carrier=session', sessionStatus.body.includes('"carrier":"session"'), true)

  console.log('\n— 场景六：纯谓词（供其它载体复用）—')
  const req = (remote, url = '/', method = 'GET', cookie = null) => ({
    url, method, socket: { remoteAddress: remote }, headers: cookie === null ? {} : { cookie },
  })
  eq('isLoopbackPeer 127.0.0.1', mod.isLoopbackPeer(req('127.0.0.1')), true)
  eq('isLoopbackPeer 127.0.0.5', mod.isLoopbackPeer(req('127.0.0.5')), true)
  eq('isLoopbackPeer ::1', mod.isLoopbackPeer(req('::1')), true)
  eq('isLoopbackPeer ::ffff:127.0.0.1', mod.isLoopbackPeer(req('::ffff:127.0.0.1')), true)
  eq('isLoopbackPeer 192.168.1.50', mod.isLoopbackPeer(req('192.168.1.50')), false)
  eq('isLoopbackPeer 无 socket', mod.isLoopbackPeer({ headers: {} }), false)
  eq('coreAdmitsHost：核心已认证', mod.coreAdmitsHost(ctx, req(LOOPBACK, '/api/x', 'POST', CORE_COOKIE)), true)
  eq('coreAdmitsHost：核心未认证', mod.coreAdmitsHost(ctx, req(LOOPBACK, '/api/x', 'POST')), false)
  eq('coreLaunchToken 反推参数名与值',
    JSON.stringify(mod.coreLaunchToken(ctx)), JSON.stringify({ name: 'token', value: CORE_TOKEN }))
  eq('coreTokenExchange：正确令牌', mod.coreTokenExchange(ctx, req(LOOPBACK, '/?token=' + CORE_TOKEN)), true)
  eq('coreTokenExchange：非根路径', mod.coreTokenExchange(ctx, req(LOOPBACK, '/index.html?token=' + CORE_TOKEN)), false)
  eq('coreTokenExchange：非 GET', mod.coreTokenExchange(ctx, req(LOOPBACK, '/?token=' + CORE_TOKEN, 'POST')), false)
  eq('coreTokenExchange：远端', mod.coreTokenExchange(ctx, req(REMOTE, '/?token=' + CORE_TOKEN)), false)
  eq('hostDirect：回环 + 核心 Cookie', mod.hostDirect(ctx, req(LOOPBACK, '/api/x', 'POST', CORE_COOKIE)), true)
  eq('hostDirect：远端 + 核心 Cookie', mod.hostDirect(ctx, req(REMOTE, '/api/x', 'POST', CORE_COOKIE)), false)

  console.log('\n— 场景七：桌面端锁（C8）—')
  const loginRoute = reg.pluginRoutes.find((r) => r.kind === 'exact' && r.path === '/dsh-webui-auth/login')
  const logoutRoute = reg.pluginRoutes.find((r) => r.kind === 'exact' && r.path === '/dsh-webui-auth/logout')
  const sessionRoute = reg.pluginRoutes.find((r) => r.kind === 'exact' && r.path === '/dsh-webui-auth/desktop-session')
  eq('注册了桌面端锁需要的三个端点', Boolean(loginRoute && logoutRoute && sessionRoute), true)

  // 换成可校验的真实 scrypt 哈希，并把有效期设为"浏览器会话"（ttl = 0）
  const PASSWORD = 'Unlock-pass-1!'
  writeFileSync(join(sandbox, 'dsh-webui-auth.json'), JSON.stringify({
    v: 3, username: 'tester', hash: await mod.hashPassword(PASSWORD), ttl: 0,
  }))

  const hostLogin = await call(loginRoute.handler, {
    url: '/dsh-webui-auth/login', method: 'POST', cookie: CORE_COOKIE, remote: LOOPBACK,
    body: JSON.stringify({ username: 'tester', password: PASSWORD }),
  })
  const hostLoginBody = json(hostLogin)
  eq('宿主直连登录成功', Boolean(hostLoginBody && hostLoginBody.ok), true)
  eq('宿主直连登录返回解锁令牌', /^[0-9a-f]{48}$/.test(String(hostLoginBody && hostLoginBody.desktopToken)), true)
  eq('并回报会话有效期（ttl=0 = 浏览器会话）', hostLoginBody && hostLoginBody.desktopTtl, 0)
  const token = hostLoginBody.desktopToken

  const remoteLogin = await call(loginRoute.handler, {
    url: '/dsh-webui-auth/login', method: 'POST', remote: REMOTE,
    body: JSON.stringify({ username: 'tester', password: PASSWORD }),
  })
  const remoteLoginBody = json(remoteLogin)
  eq('浏览器登录成功', Boolean(remoteLoginBody && remoteLoginBody.ok), true)
  eq('浏览器登录不返回解锁令牌（Cookie 才是它的凭据）', remoteLoginBody && remoteLoginBody.desktopToken, undefined)

  const good = await call(sessionRoute.handler, { url: '/dsh-webui-auth/desktop-session', method: 'POST', body: JSON.stringify({ token }) })
  eq('有效解锁令牌校验通过', Boolean(json(good) && json(good).ok), true)
  const bogusToken = 'f'.repeat(48)
  const bogus = await call(sessionRoute.handler, { url: '/dsh-webui-auth/desktop-session', method: 'POST', body: JSON.stringify({ token: bogusToken }) })
  eq('未知令牌被拒', Boolean(json(bogus) && json(bogus).ok), false)
  const malformed = await call(sessionRoute.handler, { url: '/dsh-webui-auth/desktop-session', method: 'POST', body: JSON.stringify({ token: 'nope' }) })
  eq('畸形令牌被拒', Boolean(json(malformed) && json(malformed).ok), false)

  const out1 = await call(logoutRoute.handler, {
    url: '/dsh-webui-auth/logout', method: 'POST', cookie: CORE_COOKIE, remote: LOOPBACK,
    body: JSON.stringify({ token }),
  })
  eq('宿主直连退出登录返回 ok', Boolean(json(out1) && json(out1).ok), true)
  const afterLogout = await call(sessionRoute.handler, { url: '/dsh-webui-auth/desktop-session', method: 'POST', body: JSON.stringify({ token }) })
  eq('退出后令牌立即失效（服务端已吊销）', Boolean(json(afterLogout) && json(afterLogout).ok), false)

  const hostLogin2 = await call(loginRoute.handler, {
    url: '/dsh-webui-auth/login', method: 'POST', cookie: CORE_COOKIE, remote: LOOPBACK,
    body: JSON.stringify({ username: 'tester', password: PASSWORD }),
  })
  const token2 = json(hostLogin2).desktopToken
  const remoteLogout = await call(logoutRoute.handler, { url: '/dsh-webui-auth/logout', method: 'POST', remote: REMOTE, body: JSON.stringify({ token: token2 }) })
  eq('远端退出登录照常返回 ok（只清自己的 Cookie 会话）', Boolean(json(remoteLogout) && json(remoteLogout).ok), true)
  const stillValid = await call(sessionRoute.handler, { url: '/dsh-webui-auth/desktop-session', method: 'POST', body: JSON.stringify({ token: token2 }) })
  eq('远端无法吊销宿主直连令牌（令牌只在 hostAdmitted 请求上生效）', Boolean(json(stillValid) && json(stillValid).ok), true)
} finally {
  try { rmSync(sandbox, { recursive: true, force: true }) } catch (e) { /* ignore */ }
}

console.log('\n' + pass + ' passed, ' + fail + ' failed')
process.exit(fail === 0 ? 0 : 1)
