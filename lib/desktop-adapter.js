/**
 * DSH Desktop 适配层。
 *
 * 本模块与认证逻辑**完全解耦**：不 import 主模块的任何东西，只依赖 Node 内置能力，
 * 因此可以整体删除而不影响认证本身。见文末「如何移除整个适配」。
 *
 * ── 为什么需要它（issue #8）────────────────────────────────────────────
 * DSH Desktop 的 advanced / extended 模式会在组合层**禁用核心 `ui-layout` 行**
 * （dsh-plugin-desktop 的 profile 组合按 mode 改写组合表），此时客户端 `layout`
 * 服务的唯一提供者是桌面端自己的客户端插件，而它**只在 URL 带 `dsh-desktop-*`
 * 标记时才生效** —— `parseDesktopClientEnvironment()` 在标记缺失时返回 undefined，
 * `apply()` 随即直接 return，整个桌面端客户端插件不生效。
 *
 * 任何一次落到干净 "/" 的跳转都会丢掉这些标记，于是 12 个依赖 layout 的客户端插件
 * 永远停在 pending，渲染器 30s 不上报健康，宿主弹出恢复模式对话框。已确认两条路径：
 *
 *   ① 首次登录：核心 token→cookie 交换把浏览器 303 到干净的 "/"；
 *   ② 退出后重登：客户端自行 `location.href = '/'`（lib/client.js 的 onLogout 与
 *      401 分支），服务端从头到尾没看到那个带标记的 URL 被放弃。
 *
 * ── 它做什么 ──────────────────────────────────────────────────────────
 * 主动记忆 + 补投，而不是「跳转前才记」：
 *
 *   remember()  渲染器正常加载（URL 带标记）时就把标记写进 Cookie；
 *   restore()   文档请求落到干净的 "/" 时，302 回带标记的 URL。
 *
 * 为什么必须「主动」：路径 ② 是客户端发起的跳转，服务端根本没有机会在跳转前做任何事，
 * 等它收到 `GET /` 时标记早已不在。只有在加载时就把标记落盘，才能覆盖所有丢失路径。
 *
 * 暂存**刻意不清除**：清除会引入「记住 → 立刻清掉 → 退出后无处可补」的时序陷阱，
 * 过期交给 Cookie 自身的 Max-Age（12h，且每次加载都会刷新）。
 *
 * ── 安全边界 ──────────────────────────────────────────────────────────
 * 标记按 `dsh-desktop-` 前缀**整体透传**（刻意不做硬编码白名单——DSH Desktop 将来
 * 新增一个标记时会再次静默弄坏桌面端启动，正是本 issue 的同类耦合），其中 `mode`
 * 必须是 `compatibility`/`extended`/`advanced` 之一、值长度上限 64。跳转目标恒为
 * 同源相对路径 "/"，**无开放重定向面**；网页版（无 `dsh-desktop-*` 标记）零影响。
 *
 * ── 如何移除整个适配 ──────────────────────────────────────────────────
 *   1. 删掉 index.js 里两处标着「宿主适配层」的代码块（网关 handler 内，共 3 行代码）；
 *   2. 删掉 index.js 顶部那行 import，连同它上面两行注释；
 *   3. 删掉 index.js 导出块里提到本模块的那行注释；
 *   4. 删掉本文件，并从 package.json 的 `files` 里去掉 `lib/desktop-adapter.js`。
 *
 * 已实测：只做 1+2 后 index.js 即可独立 `node --check` 通过，无任何悬空引用。
 * 认证本身不依赖本模块 —— 移除后行为等价于 0.3.3：网页版不受影响，桌面端
 * advanced / extended 模式会在登录跳转后再次出现 #8。
 *
 * ── 如何新增一个适配 ──────────────────────────────────────────────────
 * 按同样形状导出即可：
 *
 *     { remember(req, res) -> boolean, restore(req, res) -> boolean }
 *
 * remember 在网关最前面**无条件**调用；restore 在插件会话校验通过后调用，
 * 返回 true 表示已接管该请求（已发出响应，调用方应立即 return）。
 * 两个函数都只应触碰响应头，不应改变认证判定。
 */

const DESKTOP_STASH_COOKIE = 'dsh_wua_desktop'
const DESKTOP_STASH_TTL_SECONDS = 12 * 60 * 60

/** 桌面端标记的统一前缀。 */
const DESKTOP_MARKER_PREFIX = 'dsh-desktop-'

/**
 * 已知标记，仅用于固定补投时的 query 顺序；除此之外任何 `dsh-desktop-*` 键
 * 都会一并透传（前向兼容）。
 */
const DESKTOP_MARKER_KEYS = [
  'dsh-desktop-mode',
  'dsh-desktop-platform',
  'dsh-desktop-version',
  'dsh-desktop-material',
  'dsh-desktop-mica',
  'dsh-desktop-titlebar-inset',
]

/** 桌面端合法模式，与 dsh-plugin-desktop 的 MODES 对齐；其它值一律不采信。 */
const DESKTOP_MODES = new Set(['compatibility', 'extended', 'advanced'])

/** 单个标记值的长度上限，防脏 cookie 撑爆响应头。 */
const DESKTOP_MARKER_MAX_LENGTH = 64

/**
 * 读取请求 Cookie。
 * 刻意不 import 主模块的同名工具：本模块要能被单独删掉，不能反向依赖认证实现。
 */
function cookieOf(req, name) {
  const raw = req.headers && req.headers.cookie
  if (!raw) return null
  for (const part of String(raw).split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return null
}

function parseUrl(urlString) {
  try { return new URL(urlString || '/', 'http://dsh.invalid') } catch (e) { return null }
}

/**
 * 从一组 search params 里收集可透传的桌面端标记；没有可透传项时返回 null。
 * 已知键先出（顺序稳定），其余同前缀键按出现顺序跟进。
 */
function collectDesktopMarkers(params) {
  // mode 是桌面端客户端插件的硬开关：它缺失或非法时 parseDesktopClientEnvironment
  // 会直接 throw，此时补投 platform 之类的其余标记只会把渲染器推向失败，故整体放弃。
  const mode = params.get(DESKTOP_MARKER_PREFIX + 'mode')
  if (mode === null || !DESKTOP_MODES.has(mode)) return null
  const markers = []
  const seen = new Set()
  const take = (key) => {
    if (seen.has(key)) return
    const value = params.get(key)
    if (value === null || value === '' || value.length > DESKTOP_MARKER_MAX_LENGTH) return
    seen.add(key)
    markers.push([key, value])
  }
  for (const key of DESKTOP_MARKER_KEYS) take(key)
  for (const key of params.keys()) {
    if (key.startsWith(DESKTOP_MARKER_PREFIX)) take(key)
  }
  return markers.length > 0 ? markers : null
}

/** 从 URL 中提取可透传的桌面端标记；没有可透传项时返回 null。 */
function desktopMarkersOf(urlString) {
  const url = parseUrl(urlString)
  if (url === null) return null
  return collectDesktopMarkers(url.searchParams)
}

/** 暂存标记的 Set-Cookie 值。 */
function desktopStashCookie(markers) {
  const payload = markers.map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&')
  return DESKTOP_STASH_COOKIE + '=' + encodeURIComponent(payload) +
    '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + DESKTOP_STASH_TTL_SECONDS
}

/** 读出暂存 cookie 并还原成 query 串（不含 "?"）；不可用/非法时返回 null。 */
function desktopStashQuery(req) {
  const raw = cookieOf(req, DESKTOP_STASH_COOKIE)
  if (!raw) return null
  let decoded = null
  try { decoded = decodeURIComponent(raw) } catch (e) { return null }
  // 走与提取端同一套规则：暂存内容来自客户端 Cookie，同样要过滤。
  // 这套对称性是有承重的——补投出的 URL 必然能被 desktopMarkersOf 认出来，
  // restore() 才不会在同一份标记上反复跳转。改任一侧都要同步改另一侧。
  const markers = collectDesktopMarkers(new URLSearchParams(decoded))
  if (markers === null) return null
  return markers.map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&')
}

/**
 * 记住本次文档请求 URL 上的桌面端标记。
 *
 * 必须是「主动记忆」而非「跳转前才记」：退出登录是客户端自己 `location.href = '/'`，
 * 服务端根本没机会看到那个带标记的 URL 被放弃——等它看到 `GET /` 时标记早已不在，
 * 无从暂存。因此在渲染器正常加载（URL 带标记）时就落盘，之后无论标记在哪一步丢失
 * （退出重登、会话过期、核心 token 交换、深链）都能补投回来。
 *
 * @returns true 表示写入了暂存 Cookie。
 */
function remember(req, res) {
  if (req.method !== 'GET') return false
  const url = parseUrl(req.url)
  if (url === null || url.pathname !== '/') return false
  const markers = desktopMarkersOf(req.url)
  if (markers === null) return false
  res.setHeader('Set-Cookie', desktopStashCookie(markers))
  return true
}

/**
 * 文档请求落到干净的 "/" 时，把记住的桌面端标记补回 URL。
 * 刻意不清除暂存（见文件顶部说明），过期交给 Cookie 自身的 Max-Age。
 *
 * @returns true 表示已接管该请求（已发出 302，调用方应立即 return）。
 */
function restore(req, res) {
  if (req.method !== 'GET') return false
  const pending = desktopStashQuery(req)
  if (pending === null) return false
  const url = parseUrl(req.url)
  if (url === null || url.pathname !== '/') return false
  // 核心正在做 token→cookie 交换：必须放行，交换完成后它自己会 303 到干净的 "/"。
  // 若在这里抢跳，核心的 dsh-auth-* cookie 永远拿不到，/api 会全 401。
  if (url.searchParams.has('token')) return false
  // 本次文档请求已经带标记，桌面端能正常启动，无需干预。
  if (desktopMarkersOf(req.url) !== null) return false
  res.writeHead(302, { location: '/?' + pending })
  res.end()
  return true
}

export const desktopAdapter = { name: 'dsh-desktop', remember, restore }

// 纯函数供回归测试直接调用（见 test/redirect-scheme.test.mjs）
export {
  remember, restore,
  desktopMarkersOf, desktopStashCookie, desktopStashQuery, collectDesktopMarkers,
  DESKTOP_STASH_COOKIE, DESKTOP_MARKER_KEYS, DESKTOP_STASH_TTL_SECONDS,
}
