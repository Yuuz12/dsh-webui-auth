/**
 * 登录后跳转目标（scheme/authority）回归测试 —— 覆盖 issue #6 / #7。
 *
 * 运行：node test/redirect-scheme.test.mjs   （或 npm test）
 * 零依赖，直接 import 插件模块并调用导出的纯函数。
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { resolveRedirectScheme, postLoginRedirect } from '../index.js'
// DSH Desktop 适配层的纯函数直接测其所在模块，不经过 index.js 转出
import {
  desktopMarkersOf, desktopStashCookie, desktopStashQuery,
  remember as rememberDesktopMarkers, restore as restoreDesktopMarkers,
} from '../lib/desktop-adapter.js'

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

// 伪造 ctx：settings/section、webServer.port、connection.authenticatedUrl
function mkCtx(settings, port) {
  return {
    get(ns) {
      if (ns === 'settings') {
        return settings === undefined ? undefined : { get: (k) => settings[k] }
      }
      if (ns === 'webServer') return { port: port || 3080 }
      if (ns === 'connection') {
        return { authenticatedUrl: (base) => base + '/?token=abc' }
      }
      return undefined
    },
  }
}
const req = (headers, encrypted) => ({
  headers,
  socket: { encrypted: !!encrypted, remoteAddress: '127.0.0.1' },
})
const PUBLIC = { 'remote-web-ui': { publicBaseUrl: 'https://www.example.com:8443' } }

console.log('— resolveRedirectScheme：优先级 —')
eq('无任何信号（回环直连）', resolveRedirectScheme(mkCtx({}), req({ host: '127.0.0.1:3080' }), '127.0.0.1:3080'), 'http')
eq('XFP=https（#7 拓扑）', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example:8443', 'x-forwarded-proto': 'https' }), 'dsh.example:8443'), 'https')
eq('XFP 多级代理取最左', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', 'x-forwarded-proto': 'https, http' }), 'dsh.example'), 'https')
eq('XFP 大小写/空格容错', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', 'x-forwarded-proto': ' HTTPS ' }), 'dsh.example'), 'https')
eq('Forwarded proto=https', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', forwarded: 'for=1.2.3.4;proto=https;host=dsh.example' }), 'dsh.example'), 'https')
eq('Forwarded proto 居首', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', forwarded: 'proto=https' }), 'dsh.example'), 'https')
eq('Forwarded 无 proto 回落 http', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', forwarded: 'for=1.2.3.4' }), 'dsh.example'), 'http')
eq('socket.encrypted（插件直接终结 TLS）', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example:3080' }, true), 'dsh.example:3080'), 'https')
eq('publicBaseUrl authority 匹配', resolveRedirectScheme(mkCtx(PUBLIC), req({ host: 'www.example.com:8443' }), 'www.example.com:8443'), 'https')
eq('publicBaseUrl 优先于矛盾的 XFP', resolveRedirectScheme(mkCtx(PUBLIC), req({ host: 'www.example.com:8443', 'x-forwarded-proto': 'http' }), 'www.example.com:8443'), 'https')

console.log('\n— resolveRedirectScheme：默认端口规范化 —')
const sDefault = mkCtx({ 'remote-web-ui': { publicBaseUrl: 'https://a.com' } })
eq('https://a.com + Host a.com:443', resolveRedirectScheme(sDefault, req({ host: 'a.com:443' }), 'a.com:443'), 'https')
eq('https://a.com + Host a.com', resolveRedirectScheme(sDefault, req({ host: 'a.com' }), 'a.com'), 'https')
eq('https://a.com + Host a.com:8443（端口不符不采信）', resolveRedirectScheme(sDefault, req({ host: 'a.com:8443' }), 'a.com:8443'), 'http')

console.log('\n— resolveRedirectScheme：必须忽略的非法输入 —')
eq('XFP 任意 scheme 注入', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', 'x-forwarded-proto': 'javascript:alert(1)' }), 'dsh.example'), 'http')
eq('XFP CRLF 头注入', resolveRedirectScheme(mkCtx({}), req({ host: 'dsh.example', 'x-forwarded-proto': 'https\r\nx-evil: 1' }), 'dsh.example'), 'http')
eq('publicBaseUrl 非 http(s)', resolveRedirectScheme(mkCtx({ 'remote-web-ui': { publicBaseUrl: 'ftp://a.com' } }), req({ host: 'a.com' }), 'a.com'), 'http')
eq('publicBaseUrl 垃圾值', resolveRedirectScheme(mkCtx({ 'remote-web-ui': { publicBaseUrl: 'not a url' } }), req({ host: 'a.com' }), 'a.com'), 'http')
eq('settings 服务缺失', resolveRedirectScheme(mkCtx(undefined), req({ host: 'a.com' }), 'a.com'), 'http')
eq('内网域名不得被猜测成 https', resolveRedirectScheme(mkCtx({}), req({ host: 'nas.local:3080' }), 'nas.local:3080'), 'http')

console.log('\n— 开放重定向防护：publicBaseUrl 只对匹配的 Host 生效 —')
eq('局域网直连不被改写到公网', resolveRedirectScheme(mkCtx(PUBLIC), req({ host: '192.168.3.5:3080' }), '192.168.3.5:3080'), 'http')
eq('其他域名 + XFP 仍按 XFP', resolveRedirectScheme(mkCtx(PUBLIC), req({ host: 'lan.internal:8443', 'x-forwarded-proto': 'https' }), 'lan.internal:8443'), 'https')
eq('其他域名 + 无信号 → http（不跳公网）', resolveRedirectScheme(mkCtx(PUBLIC), req({ host: 'evil.example' }), 'evil.example'), 'http')

console.log('\n— postLoginRedirect —')
eq('#7 复现：XFP=https → https 跳转', postLoginRedirect(mkCtx({}), req({ host: 'www.kongjianzhan.top:8443', 'x-forwarded-proto': 'https' })), 'https://www.kongjianzhan.top:8443/?token=abc')
eq('#7 复现：publicBaseUrl → https 跳转', postLoginRedirect(mkCtx({ 'remote-web-ui': { publicBaseUrl: 'https://www.kongjianzhan.top:8443' } }), req({ host: 'www.kongjianzhan.top:8443' })), 'https://www.kongjianzhan.top:8443/?token=abc')
eq('#6：authority 取自请求 Host（非写死 127.0.0.1）', postLoginRedirect(mkCtx({}), req({ host: 'dsh.homelab.lan:8443' })), 'http://dsh.homelab.lan:8443/?token=abc')
eq('无 Host 头 → 回环 http 兜底', postLoginRedirect(mkCtx({}), req({})), 'http://127.0.0.1:3080/?token=abc')
eq('无 Host 头 + XFP=https → 回环仍 http', postLoginRedirect(mkCtx({}), req({ 'x-forwarded-proto': 'https' })), 'http://127.0.0.1:3080/?token=abc')
eq('host 非字符串 → 回环兜底', postLoginRedirect(mkCtx({}), { headers: { host: 123 }, socket: {} }), 'http://127.0.0.1:3080/?token=abc')
eq('connection 服务缺失 → "/"', postLoginRedirect({ get: () => undefined }, req({ host: 'a.com' })), '/')

console.log('\n— 前端登录页兜底（https 页面收到同源 http:// 跳转）—')
const here = dirname(fileURLToPath(import.meta.url))
const src = readFileSync(join(here, '..', 'index.js'), 'utf8')
const start = src.indexOf('const LOGIN_PAGE = `')
const rawLiteral = src.slice(start + 'const LOGIN_PAGE = `'.length, src.indexOf('`', src.indexOf('</html>', start)))
// 用 JS 自身求值模板字面量，等价于模块加载时的产物（含转义还原）
const page = new Function('return `' + rawLiteral + '`')() // eslint-disable-line no-new-func
const scripts = [...page.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1])
eq('登录页内联 script 数量', String(scripts.length), '2')
scripts.forEach((body, i) => {
  let err = ''
  try { new Function(body) } catch (e) { err = e.message }
  eq('登录页 script#' + (i + 1) + ' 语法', err === '' ? 'OK' : err, 'OK')
})
const goToSrc = /function goTo\(target\) \{[\s\S]*?\n\}/.exec(page)[0]
function runGoTo(target, protocol, host) {
  const navigated = []
  const location = {
    protocol,
    host,
    get href() { return navigated[navigated.length - 1] },
    set href(v) { navigated.push(v) },
  }
  new Function('location', 'URL', goToSrc + '\nreturn goTo(arguments[2]);')(location, URL, target) // eslint-disable-line no-new-func
  return navigated[navigated.length - 1]
}
eq('https 页 + 同源 http:// → 升级 https', runGoTo('http://dsh.example:8443/?token=abc', 'https:', 'dsh.example:8443'), 'https://dsh.example:8443/?token=abc')
eq('https 页 + 同源 https:// → 不动', runGoTo('https://dsh.example:8443/?token=abc', 'https:', 'dsh.example:8443'), 'https://dsh.example:8443/?token=abc')
eq('http 页 + http:// → 不动（不降级）', runGoTo('http://192.168.3.5:3080/?token=abc', 'http:', '192.168.3.5:3080'), 'http://192.168.3.5:3080/?token=abc')
eq('https 页 + 异源 http:// → 不动', runGoTo('http://evil.example/?token=abc', 'https:', 'dsh.example:8443'), 'http://evil.example/?token=abc')
eq('redirect 缺失 → "/"', runGoTo(undefined, 'https:', 'dsh.example'), '/')
eq('redirect 非字符串 → "/"', runGoTo({ evil: 1 }, 'https:', 'dsh.example'), '/')

// ============================================================
// #8：DSH Desktop advanced / extended 模式的桌面端标记透传
// ============================================================

console.log('\n— #8 标记提取与白名单 —')
const MK = '/?dsh-desktop-mode=advanced&dsh-desktop-platform=win32&dsh-desktop-version=2.0.9&dsh-desktop-material=mica&dsh-desktop-mica=1&dsh-desktop-titlebar-inset=36&foo=bar'
eq('提取全部已知标记、忽略未知键', JSON.stringify(desktopMarkersOf(MK)), JSON.stringify([
  ['dsh-desktop-mode', 'advanced'], ['dsh-desktop-platform', 'win32'], ['dsh-desktop-version', '2.0.9'],
  ['dsh-desktop-material', 'mica'], ['dsh-desktop-mica', '1'], ['dsh-desktop-titlebar-inset', '36'],
]))
eq('未知的同前缀标记一并透传（前向兼容）',
  JSON.stringify(desktopMarkersOf('/?dsh-desktop-mode=advanced&dsh-desktop-future-thing=42')),
  JSON.stringify([['dsh-desktop-mode', 'advanced'], ['dsh-desktop-future-thing', '42']]))
eq('非同前缀键被忽略', JSON.stringify(desktopMarkersOf('/?dsh-desktop-mode=advanced&evil=1&token=x')),
  JSON.stringify([['dsh-desktop-mode', 'advanced']]))
eq('非法 mode → 整体放弃（含 platform）', desktopMarkersOf('/?dsh-desktop-mode=bogus&dsh-desktop-platform=win32'), null)
eq('mode 缺失 → 整体放弃', desktopMarkersOf('/?dsh-desktop-platform=win32'), null)
eq('无标记 → null', desktopMarkersOf('/?token=abc'), null)
eq('空 search → null', desktopMarkersOf('/'), null)
eq('超长值被丢弃、mode 保留', JSON.stringify(desktopMarkersOf('/?dsh-desktop-mode=advanced&dsh-desktop-platform=' + 'x'.repeat(65))),
  JSON.stringify([['dsh-desktop-mode', 'advanced']]))
eq('空值被丢弃', JSON.stringify(desktopMarkersOf('/?dsh-desktop-mode=advanced&dsh-desktop-platform=')),
  JSON.stringify([['dsh-desktop-mode', 'advanced']]))

console.log('\n— #8 暂存 cookie 编解码 —')
const cookie = desktopStashCookie(desktopMarkersOf(MK))
eq('cookie 名', cookie.slice(0, cookie.indexOf('=')), 'dsh_wua_desktop')
eq('HttpOnly + SameSite=Lax + Path=/', /HttpOnly/.test(cookie) && /SameSite=Lax/.test(cookie) && /Path=\//.test(cookie), true)
eq('Max-Age=12h（覆盖退出后重登的时间窗）', /Max-Age=43200(;|$)/.test(cookie), true)
eq('值整体已编码（无裸 & / ;）', /[&;]/.test(cookie.split(';')[0]), false)
const stashValue = cookie.split(';')[0].split('=').slice(1).join('=')
eq('读回并还原顺序', desktopStashQuery({ headers: { cookie: 'dsh_wua_desktop=' + stashValue } }),
  'dsh-desktop-mode=advanced&dsh-desktop-platform=win32&dsh-desktop-version=2.0.9&dsh-desktop-material=mica&dsh-desktop-mica=1&dsh-desktop-titlebar-inset=36')
eq('mode 缺失 → 放弃', desktopStashQuery({ headers: { cookie: 'dsh_wua_desktop=' + encodeURIComponent('dsh-desktop-platform=win32') } }), null)
eq('mode 非法 → 放弃', desktopStashQuery({ headers: { cookie: 'dsh_wua_desktop=' + encodeURIComponent('dsh-desktop-mode=bogus') } }), null)
eq('cookie 不存在 → null', desktopStashQuery({ headers: {} }), null)
eq('cookie 解码失败 → null', desktopStashQuery({ headers: { cookie: 'dsh_wua_desktop=%E0%A4%A' } }), null)

// 模拟浏览器 cookie jar + 网关决策顺序（与 index.js 的 prefix '' 处理器一致）
function mkBrowser() {
  const jar = new Map()
  const applySetCookie = (sc) => {
    if (!sc) return
    const parts = String(sc).split(';').map((s) => s.trim())
    const eq2 = parts[0].indexOf('=')
    if (eq2 === -1) return
    const name = parts[0].slice(0, eq2)
    const value = parts[0].slice(eq2 + 1)
    const maxAge = parts.find((p) => p.toLowerCase().startsWith('max-age='))
    if (value === '' || (maxAge && Number(maxAge.slice('max-age='.length)) === 0)) jar.delete(name)
    else jar.set(name, value)
  }
  const request = (url, method) => {
    const headers = {}
    if (jar.size > 0) headers.cookie = [...jar.entries()].map(([k, v]) => k + '=' + v).join('; ')
    const out = { status: 0, headers: {}, headersSent: false }
    return {
      req: { url, method: method || 'GET', headers },
      out,
      res: {
        get headersSent() { return out.headersSent },
        setHeader(k, v) { out.headers[k.toLowerCase()] = v },
        writeHead(status, extra) {
          out.status = status
          if (extra) for (const k of Object.keys(extra)) out.headers[k.toLowerCase()] = extra[k]
          out.headersSent = true
        },
        end() { applySetCookie(out.headers['set-cookie']) },
        destroy() {},
      },
    }
  }
  return { jar, request }
}

// 网关决策（顺序与 index.js 的 prefix '' 处理器一致：先主动记忆，再走认证分支）
function gate(browser, url, opts) {
  const { req, res, out } = browser.request(url)
  rememberDesktopMarkers(req, res)
  if (opts.authenticated) {
    if (restoreDesktopMarkers(req, res)) return { out, action: 'restore' }
    if (opts.coreUnauthorized) {
      res.writeHead(302, { location: 'http://127.0.0.1:3080/?token=tok' })
      res.end()
      return { out, action: 'core-token-hop' }
    }
    res.writeHead(200)
    res.end('index')
    return { out, action: 'serve' }
  }
  res.writeHead(302, { location: '/dsh-webui-auth/login' })
  res.end()
  return { out, action: 'login' }
}

const DESKTOP_URL = '/?dsh-desktop-mode=advanced&dsh-desktop-platform=win32&dsh-desktop-version=2.0.9'

console.log('\n— #8 场景一：全新登录（插件未登录 + 核心未认领）—')
const b1 = mkBrowser()
const s1 = gate(b1, DESKTOP_URL, { authenticated: false })
eq('① 初始请求被送去登录页', s1.out.headers.location, '/dsh-webui-auth/login')
eq('① 同时记住桌面端标记', b1.jar.has('dsh_wua_desktop'), true)
const s2 = gate(b1, '/?token=tok', { authenticated: true, coreUnauthorized: true })
eq('② 核心 token 交换请求被放行（不抢跳）', s2.action, 'core-token-hop')
const s3 = gate(b1, '/', { authenticated: true })
eq('③ 干净 "/" 被补投回带标记 URL', s3.out.headers.location, DESKTOP_URL)
const s4 = gate(b1, s3.out.headers.location, { authenticated: true })
eq('④ 带标记 URL 正常出 index', s4.action, 'serve')
eq('④ 无二次跳转', s4.out.status, 200)

console.log('\n— #8 场景二：已有插件会话、核心 cookie 缺失（核心重启后）—')
const b2 = mkBrowser()
b2.jar.set('dsh_wua_session', 'sess')
const EXT_URL = '/?dsh-desktop-mode=extended&dsh-desktop-platform=darwin'
const t1 = gate(b2, EXT_URL, { authenticated: true, coreUnauthorized: true })
eq('① 带标记的加载直接放行（不被自己补投打断）', t1.action, 'core-token-hop')
eq('① 标记已记住', b2.jar.has('dsh_wua_desktop'), true)
const t2 = gate(b2, '/?token=tok', { authenticated: true, coreUnauthorized: true })
eq('② token 请求放行', t2.action, 'core-token-hop')
const t3 = gate(b2, '/', { authenticated: true })
eq('③ 干净 "/" 补投', t3.out.headers.location, EXT_URL)

console.log('\n— #8 场景三：网页版 / 无标记请求零影响 —')
const b3 = mkBrowser()
gate(b3, '/', { authenticated: false })
eq('未登录根请求不写暂存 cookie', b3.jar.has('dsh_wua_desktop'), false)
const w1 = gate(b3, '/', { authenticated: true })
eq('干净 "/" 直接出 index', w1.action, 'serve')
const w2 = gate(b3, '/assets/index-abc.js?dsh-desktop-mode=advanced', { authenticated: true })
eq('资源路径永不补投', w2.action, 'serve')
eq('资源请求也不写暂存 cookie', b3.jar.has('dsh_wua_desktop'), false)

console.log('\n— #8 场景四：补投目标自身可终止，不产生重定向循环 —')
const b4 = mkBrowser()
b4.jar.set('dsh_wua_session', 'sess')
b4.jar.set('dsh_wua_desktop', encodeURIComponent('dsh-desktop-mode=advanced&dsh-desktop-platform=win32'))
const r1 = gate(b4, '/', { authenticated: true })
eq('干净 "/" 补投', r1.action, 'restore')
eq('补投目标带标记', r1.out.headers.location, '/?dsh-desktop-mode=advanced&dsh-desktop-platform=win32')
eq('落回补投目标后不再跳转', gate(b4, r1.out.headers.location, { authenticated: true }).action, 'serve')
eq('暂存保留（供下次丢标记时复用）', b4.jar.has('dsh_wua_desktop'), true)

console.log('\n— #8 场景五：退出登录后重新登录（本次报告的问题）—')
const b5 = mkBrowser()
b5.jar.set('dsh_wua_session', 'sess')
// ① 已登录，渲染器停在带标记的 URL 上 —— 这一步就要把标记记住，
//    因为退出时是客户端自己 location.href = '/'，服务端看不到标记被放弃。
const o1 = gate(b5, DESKTOP_URL, { authenticated: true })
eq('① 正常出 index', o1.action, 'serve')
eq('① 标记已在加载时被记住', b5.jar.has('dsh_wua_desktop'), true)
// ② 用户在设置里点「退出登录」：插件清掉会话，客户端跳到干净的 "/"
b5.jar.delete('dsh_wua_session')
const o2 = gate(b5, '/', { authenticated: false })
eq('② 退出后落到干净 "/" → 登录页', o2.out.headers.location, '/dsh-webui-auth/login')
eq('② 标记仍然记得（0.3.4 在此丢失）', b5.jar.has('dsh_wua_desktop'), true)
// ③ 重新输入账号密码 → 核心 token→cookie 交换
const o3 = gate(b5, '/?token=tok', { authenticated: true, coreUnauthorized: true })
eq('③ token 交换放行', o3.action, 'core-token-hop')
// ④ 核心 303 到干净的 "/" → 补投
const o4 = gate(b5, '/', { authenticated: true })
eq('④ 干净 "/" 被补投回带标记 URL', o4.out.headers.location, DESKTOP_URL)
eq('⑤ 带标记 URL 正常出 index', gate(b5, o4.out.headers.location, { authenticated: true }).action, 'serve')

console.log('\n— DSH Desktop 适配层的可摘除性 —')
// 适配层要能被整体删掉而不影响认证，因此它必须自包含（不反向 import 主模块），
// 且主模块对它的依赖必须只有网关里那两个调用点。这里把这两条约束钉住。
const adapterSrc = readFileSync(join(here, '..', 'lib', 'desktop-adapter.js'), 'utf8')
eq('适配层不 import 任何模块（自包含）', /^[ \t]*import[ \t]/m.test(adapterSrc) ? 'has-import' : 'clean', 'clean')
const indexSrc = readFileSync(join(here, '..', 'index.js'), 'utf8')
const callSites = [...indexSrc.matchAll(/desktopAdapter\.(\w+)\(/g)].map((m) => m[1])
eq('index.js 只在网关里调用 remember + restore', JSON.stringify(callSites), JSON.stringify(['remember', 'restore']))
eq('index.js 只在顶部 import 一次适配层',
  (indexSrc.match(/from '\.\/lib\/desktop-adapter\.js'/g) || []).length, 1)

console.log('\n' + pass + ' passed, ' + fail + ' failed')
process.exit(fail === 0 ? 0 : 1)
