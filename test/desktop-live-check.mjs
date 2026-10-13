/**
 * 官方桌面端现场自检（只读、无需任何凭据）。
 *
 * 用途：桌面端重启（或热加载）之后，一条命令回答"插件到底有没有在桌面端宿主里生效、
 * 口令闸门有没有被放松"。全部是匿名 GET，不改动任何状态，也不读取任何密钥。
 *
 * 用法：
 *   node test/desktop-live-check.mjs [--port 19387]
 *
 * 判定依据（都取自插件独有的响应特征，核心侧无法伪造）：
 *   · /dsh-webui-auth/status → 401 + JSON 体 {"error":"unauthorized"}
 *       这个 exact 路由与 JSON 体只有插件注册了才存在；
 *   · /dsh-webui-auth/login  → HTML 里 `var MODE = "login"|"setup"`
 *       插件登录页；mode=login 表示认证已启用；
 *   · GET /                  → 302 + location: /dsh-webui-auth/login
 *       插件文档闸门在守（没有插件时核心只会回 401 纯文本）；
 *   · GET /plugins/events    → 401
 *       顶层 exact 路由同样被闸门覆盖（0.3.6 起；更早版本这里匿名可读，会把整个客户端
 *       插件图推给任何人）。
 *
 * 实现刻意只用 node:net 手写 HTTP/1.1（Connection: close），不碰 fetch/undici：
 * SSE 端点与 undici 的退出拆卸都会让这个短命脚本在 Node 24 上抛 libuv 断言。
 *
 * 退出码：插件已加载并守门 = 0；插件未加载 = 1；连不上宿主 = 2。
 */
import { readdirSync, statSync } from 'node:fs'
import net from 'node:net'
import { homedir } from 'node:os'
import { join } from 'node:path'

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback
}

const PORT = Number(argValue('--port', '19387'))
const LOGS_DIR = join(homedir(), 'AppData', 'Roaming', '@deepseek-ai', 'dsh-desktop', 'logs')

/** 去掉 chunked 分块框架，便于人读与子串比对。 */
function dechunk(raw) {
  let out = ''
  let rest = raw
  for (;;) {
    const nl = rest.indexOf('\r\n')
    if (nl === -1) break
    const size = parseInt(rest.slice(0, nl).trim(), 16)
    if (!Number.isFinite(size) || size <= 0) break
    out += rest.slice(nl + 2, nl + 2 + size)
    rest = rest.slice(nl + 2 + size + 2)
  }
  return out
}

/** 单次匿名 GET。headOnly 用于流式端点：只读状态行就断开。 */
function httpGet(path, { timeoutMs = 4000, headOnly = false } = {}) {
  return new Promise((resolve) => {
    const socket = net.connect(PORT, '127.0.0.1')
    let buf = ''
    let settled = false
    const parse = (head, body) => {
      const lines = head.split('\r\n')
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0] || '')
      let location = null
      let chunked = false
      for (const line of lines.slice(1)) {
        const i = line.indexOf(':')
        if (i <= 0) continue
        const name = line.slice(0, i).toLowerCase()
        if (name === 'location') location = line.slice(i + 1).trim()
        if (name === 'transfer-encoding' && line.slice(i + 1).toLowerCase().includes('chunked')) chunked = true
      }
      return { status: m ? Number(m[1]) : 0, location, body: chunked ? dechunk(body) : body }
    }
    const finish = (result) => {
      if (settled) return
      settled = true
      try { socket.destroy() } catch (e) { /* ignore */ }
      resolve(result)
    }
    socket.setTimeout(timeoutMs, () => finish({ status: 0, location: null, body: buf, error: 'timeout' }))
    socket.on('error', (e) => finish({ status: 0, location: null, body: '', error: e && e.message ? e.message : String(e) }))
    socket.on('connect', () => {
      socket.write('GET ' + path + ' HTTP/1.1\r\n' +
        'Host: 127.0.0.1:' + PORT + '\r\n' +
        'User-Agent: dsh-webui-auth-live-check\r\n' +
        'Accept: */*\r\n' +
        'Connection: close\r\n\r\n')
    })
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8')
      const headEnd = buf.indexOf('\r\n\r\n')
      if (headEnd === -1) return
      if (headOnly) finish(parse(buf.slice(0, headEnd), ''))
      else if (buf.length > 256 * 1024) finish(parse(buf.slice(0, headEnd), buf.slice(headEnd + 4)))
    })
    socket.on('end', () => {
      const headEnd = buf.indexOf('\r\n\r\n')
      if (headEnd === -1) finish({ status: 0, location: null, body: '' })
      else finish(parse(buf.slice(0, headEnd), buf.slice(headEnd + 4)))
    })
  })
}

const status = await httpGet('/dsh-webui-auth/status')
if (status.status === 0) {
  console.error('无法连接 127.0.0.1:' + PORT + ' —— 桌面端没在运行？(' + (status.error || 'no response') + ')')
  process.exit(2)
}

const pluginLoaded = status.status === 401 && status.body.includes('"error":"unauthorized"')
const login = await httpGet('/dsh-webui-auth/login')
const mode = /var MODE = "([a-z]+)"/.exec(login.body)
const root = await httpGet('/')
const documentGate = root.status === 302 && String(root.location || '').includes('/dsh-webui-auth/login')
const api = await httpGet('/api/settings/describe')
const eventsAnon = (await httpGet('/plugins/events', { headOnly: true })).status

let newestCrash = null
try {
  for (const file of readdirSync(LOGS_DIR).filter((f) => f.startsWith('crash-'))) {
    const stat = statSync(join(LOGS_DIR, file))
    if (newestCrash === null || stat.mtimeMs > newestCrash.mtimeMs) newestCrash = { file, mtime: stat.mtime, mtimeMs: stat.mtimeMs }
  }
} catch (e) { /* 目录不存在 */ }

const line = (k, v) => console.log('  ' + k.padEnd(22) + v)
console.log('桌面端现场自检 · http://127.0.0.1:' + PORT)
line('插件已加载', pluginLoaded ? '是（/dsh-webui-auth/status 返回插件专属 JSON）' : '否（该路由不存在或响应不符）')
line('认证状态', mode === null ? '未知（未取到插件登录页）' : (mode[1] === 'login' ? '已启用（MODE=login）' : '未配置（MODE=setup）'))
line('文档闸门', documentGate ? '在守（/ → 302 ' + root.location + '）' : '未见插件跳转（/ → ' + root.status + '，核心 401 说明插件未接管）')
line('匿名 /api', api.status + ' ' + (api.body || '').replace(/\r?\n/g, ' ').trim().slice(0, 40))
line('匿名 /plugins/events', eventsAnon + (eventsAnon === 401 ? '（exact 路由已被闸门覆盖）' : (eventsAnon === 200 ? '（旁路：该实例仍是未覆盖 exact 路由的旧代码）' : '')))
line('最近 crash 日志', newestCrash === null ? '无' : newestCrash.file + '  (' + newestCrash.mtime.toISOString() + ')')

console.log('')
if (pluginLoaded && documentGate) {
  console.log('结论：插件已在桌面端宿主里生效，且匿名访问仍被挡在闸门外。')
  if (eventsAnon !== 401) console.log('提示：该实例尚未覆盖 /plugins/events（顶层 exact 路由）——桌面端重启后会带上这层覆盖。')
  process.exitCode = 0
} else {
  console.log('结论：插件当前未在桌面端生效（或未启用）——若刚重启过，请检查 profile 的 dsh.profile.bundles 是否含 dsh-webui-auth。')
  process.exitCode = 1
}
