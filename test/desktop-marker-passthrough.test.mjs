/**
 * #8 端到端回归：DSH Desktop advanced / extended 模式下的桌面端标记透传。
 *
 * 与 redirect-scheme.test.mjs 里的纯函数测试不同，这里驱动的是 **apply() 真正注册的
 * prefix "" 处理器**，避免测试里复刻的决策顺序与实现漂移。
 *
 * index.js 在模块加载时就把 DATA_DIR 定死在自己的目录下（MODULE_DIR），因此测试把
 * index.js 复制到一个临时目录再 import —— 数据文件（凭据 / 会话 / 审计）全部落在临时
 * 目录里，绝不触碰仓库中的真实 sessions.jsonl。
 *
 * 运行：node test/desktop-marker-passthrough.test.mjs
 */
import { mkdtempSync, copyFileSync, cpSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

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
const sandbox = mkdtempSync(join(tmpdir(), 'dsh-webui-auth-8-'))

try {
  // 沙箱里放一份插件（index.js + lib/）+ 凭据 + 一条有效会话
  copyFileSync(join(pluginRoot, 'index.js'), join(sandbox, 'index.js'))
  cpSync(join(pluginRoot, 'lib'), join(sandbox, 'lib'), { recursive: true })
  writeFileSync(join(sandbox, 'dsh-webui-auth.json'), JSON.stringify({
    v: 3, username: 'tester', hash: 'scrypt:32768:8:1:AAAA:BBBB', ttl: 72,
  }))
  const SESSION_TOKEN = 'testtoken'
  writeFileSync(join(sandbox, 'sessions.jsonl'),
    JSON.stringify({ op: 'add', token: SESSION_TOKEN, sess: { username: 'tester', expiresAt: Date.now() + 3600_000, browser: false } }) + '\n')

  const mod = await import(pathToFileURL(join(sandbox, 'index.js')).href)

  // ---- 伪造 ctx：webServer 路由表 + fallback（模拟核心 BrowserAuth）+ connection ----
  const registered = []
  const core = { cookieIssued: false }

  const webServer = {
    port: 3080,
    prefixes: new Map(),
    upgrades: new Map(),
    exact: new Map(),
    async fallback(req, res) {
      const url = new URL(req.url, 'http://dsh.invalid')
      // 模拟核心 BrowserAuth.authorizeIndex：带 launch token 的根请求换 cookie 后 303 到干净 "/"
      if (url.pathname === '/' && url.searchParams.has('token')) {
        core.cookieIssued = true
        res.writeHead(303, { location: '/', 'set-cookie': 'dsh-auth-core=issued' })
        res.end()
        return
      }
      if (url.pathname === '/' && core.cookieIssued) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end('<!doctype html>INDEX' + url.search)
        return
      }
      res.writeHead(404)
      res.end('not found')
    },
    register(route) { registered.push(route); return () => {} },
  }

  const connection = {
    requestRejection(req) {
      return (req.headers.cookie || '').includes('dsh-auth-core=') ? undefined : 401
    },
    authenticatedUrl(base) { return base + '/?token=tok' },
  }

  const ctx = {
    fs: {
      async resolve(p) { return p },
      async readText(p) { try { return readFileSync(p, 'utf8') } catch (e) { return null } },
      async writeText() {},
    },
    effect(fn) { const d = fn(); return () => { if (typeof d === 'function') d() } },
    logger: { info() {}, warn() {}, error() {} },
    webServer,
    get(ns) {
      if (ns === 'webServer') return webServer
      if (ns === 'connection') return connection
      if (ns === 'settings') return { get: () => undefined }
      return undefined
    },
  }

  await mod.apply(ctx)

  const gate = registered.find((r) => r.kind === 'prefix' && r.path === '')
  eq('apply() 注册了 prefix "" 传输层闸门', gate !== undefined, true)

  // ---- 浏览器 cookie jar + 单次请求往返 ----
  const jar = new Map()
  function applySetCookie(sc) {
    if (!sc) return
    const parts = String(sc).split(';').map((s) => s.trim())
    const i = parts[0].indexOf('=')
    if (i === -1) return
    const name = parts[0].slice(0, i)
    const value = parts[0].slice(i + 1)
    const maxAge = parts.find((p) => p.toLowerCase().startsWith('max-age='))
    if (value === '' || (maxAge && Number(maxAge.slice('max-age='.length)) === 0)) jar.delete(name)
    else jar.set(name, value)
  }

  async function exchange(url, method = 'GET') {
    const out = { status: 0, headers: {}, body: '', headersSent: false }
    const headers = {}
    if (jar.size > 0) headers.cookie = [...jar.entries()].map(([k, v]) => k + '=' + v).join('; ')
    const res = {
      get headersSent() { return out.headersSent },
      setHeader(k, v) { out.headers[k.toLowerCase()] = v },
      writeHead(status, extra) {
        out.status = status
        if (extra) for (const k of Object.keys(extra)) out.headers[k.toLowerCase()] = extra[k]
        out.headersSent = true
      },
      end(body) {
        if (body !== undefined) out.body = String(body)
        applySetCookie(out.headers['set-cookie'])
      },
      destroy() {},
    }
    await gate.handler({ url, method, headers }, res)
    return { status: out.status, location: out.headers.location || null, body: out.body }
  }

  const DESKTOP_URL = '/?dsh-desktop-mode=advanced&dsh-desktop-platform=win32&dsh-desktop-version=2.0.9'
  const resetJar = (entries) => {
    jar.clear()
    for (const [k, v] of entries) jar.set(k, v)
  }

  console.log('\n— 场景一：全新登录（#8 复现路径）—')
  const s1 = await exchange(DESKTOP_URL)
  eq('① 初始请求被送去登录页', s1.location, '/dsh-webui-auth/login')
  eq('① 暂存了桌面端标记', jar.has('dsh_wua_desktop'), true)

  // 用户在登录页提交成功 → 插件下发会话 cookie，并把浏览器送到核心 launch-token URL
  jar.set('dsh_wua_session', SESSION_TOKEN)
  const s2 = await exchange('/?token=tok')
  eq('② token 交换被放行到核心（未被抢跳）', s2.location, '/')
  eq('② 核心已下发 cookie', core.cookieIssued, true)

  const s3 = await exchange('/')
  eq('③ 干净的 "/" 被补投回带标记 URL', s3.location, DESKTOP_URL)
  eq('③ 暂存保留（供后续丢标记时复用）', jar.has('dsh_wua_desktop'), true)

  const s4 = await exchange(s3.location)
  eq('④ 渲染器拿到 index（200）', s4.status, 200)
  eq('④ 文档 URL 保留了 dsh-desktop-mode', s4.body.includes('dsh-desktop-mode=advanced'), true)
  eq('④ 文档 URL 保留了 dsh-desktop-platform', s4.body.includes('dsh-desktop-platform=win32'), true)

  console.log('\n— 场景二：已有插件会话、核心 cookie 缺失（核心重启后）—')
  core.cookieIssued = false
  resetJar([['dsh_wua_session', SESSION_TOKEN]])
  const t1 = await exchange(DESKTOP_URL)
  eq('① 直接走核心 token 跳转', t1.location, 'http://127.0.0.1:3080/?token=tok')
  eq('① 跳转前暂存标记', jar.has('dsh_wua_desktop'), true)
  const t2 = await exchange('/?token=tok')
  eq('② token 请求放行', t2.location, '/')
  const t3 = await exchange('/')
  eq('③ 干净 "/" 补投', t3.location, DESKTOP_URL)

  console.log('\n— 场景三：网页版 / 无标记请求零影响 —')
  core.cookieIssued = true
  resetJar([['dsh_wua_session', SESSION_TOKEN], ['dsh-auth-core', 'issued']])
  const w1 = await exchange('/')
  eq('无标记的 "/" 直接出 index', w1.status, 200)
  eq('未写入暂存 cookie', jar.has('dsh_wua_desktop'), false)
  const w2 = await exchange('/assets/index-abc.js?dsh-desktop-mode=advanced')
  eq('资源路径不受影响（落到核心 404）', w2.status, 404)
  eq('资源请求也不写暂存 cookie', jar.has('dsh_wua_desktop'), false)

  console.log('\n— 场景四：补投目标自身可终止，无重定向循环 —')
  core.cookieIssued = true
  resetJar([
    ['dsh_wua_session', SESSION_TOKEN],
    ['dsh-auth-core', 'issued'],
    ['dsh_wua_desktop', encodeURIComponent('dsh-desktop-mode=advanced&dsh-desktop-platform=win32')],
  ])
  const l1 = await exchange('/')
  eq('干净 "/" 补投', l1.location, '/?dsh-desktop-mode=advanced&dsh-desktop-platform=win32')
  const l2 = await exchange(l1.location)
  eq('落回补投目标后不再跳转（200）', l2.status, 200)
  eq('暂存保留', jar.has('dsh_wua_desktop'), true)

  console.log('\n— 场景五：退出登录后重新登录（本次报告的问题）—')
  core.cookieIssued = true
  resetJar([['dsh_wua_session', SESSION_TOKEN], ['dsh-auth-core', 'issued']])
  // ① 已登录，渲染器停在带标记的 URL 上 —— 这一步就要把标记记住
  const o1 = await exchange(DESKTOP_URL)
  eq('① 正常出 index', o1.status, 200)
  eq('① 标记在加载时已被记住', jar.has('dsh_wua_desktop'), true)
  // ② 用户在设置里点「退出登录」：插件清掉会话，客户端 location.href = '/'
  jar.delete('dsh_wua_session')
  const o2 = await exchange('/')
  eq('② 退出后落到干净 "/" → 登录页', o2.location, '/dsh-webui-auth/login')
  eq('② 标记仍然记得（0.3.4 在此丢失）', jar.has('dsh_wua_desktop'), true)
  // ③ 重新输入账号密码登录 → 核心 token→cookie 交换
  jar.set('dsh_wua_session', SESSION_TOKEN)
  const o3 = await exchange('/?token=tok')
  eq('③ token 交换被放行', o3.location, '/')
  // ④ 核心 303 到干净的 "/" → 补投
  const o4 = await exchange('/')
  eq('④ 干净 "/" 被补投回带标记 URL', o4.location, DESKTOP_URL)
  const o5 = await exchange(o4.location)
  eq('⑤ 带标记 URL 正常出 index（200）', o5.status, 200)
  eq('⑤ 文档 URL 保留了 dsh-desktop-mode', o5.body.includes('dsh-desktop-mode=advanced'), true)
} finally {
  try { rmSync(sandbox, { recursive: true, force: true }) } catch (e) { /* ignore */ }
}

console.log('\n' + pass + ' passed, ' + fail + ' failed')
process.exit(fail === 0 ? 0 : 1)
