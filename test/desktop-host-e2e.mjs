/**
 * 真实宿主端到端验证：官方桌面端（DSH Desktop）的请求形状 × dsh-webui-auth 的闸门。
 *
 * 为什么需要它：`test/host-bridge.test.mjs` 用的是伪造 ctx（核心语义由测试自己模拟），
 * 而这里的每一条断言都打在**真核心**上——真 webserver、真 Connection BrowserAuth、
 * 真 `/api` RPC 桥、真 WebSocket 升级。桌面端自己那个 Host 进程端口写死 19387
 * （`dsh-desktop-host` 的 `--port 19387`），桌面端一开着就占住了；因此本脚本改用
 * 同一 runtime 的 `dsh web` surface + 自由端口驱动**同一份 Web 应用核心**。
 *
 * 探针复刻的是 app.asar lib/main.js 里真实发生的每一步：
 *   ① authenticateWebHost(ready.url)：fetch(url, {redirect:'manual'}) 要求 303 + set-cookie
 *      —— 版本 < 0.3.6 时插件回 302，桌面端抛 "Desktop Host authentication failed" 并弹恢复模式；
 *   ② connectDesktopWelcome：带核心凭据 POST /api/settings/describe（RPC 信封）
 *      —— 修复前全 401，欢迎页/账号面板直接失败；
 *   ③ 渲染器转发：/api、/plugins 只带核心 Cookie（shell 代理丢弃 set-cookie，插件会话落不了地）；
 *   ④ WebSocket 升级 /api/remote.mux（shell 会补 origin + cookie + sec-fetch-site）
 *      —— 修复前 401，事件流被掐断，设置页整片点不动；
 *   ⑤ 对照组：无凭据 / 错误 token 的浏览器请求**仍必须**被插件拦下（口令闸门不能被削弱）。
 *
 * 用法（在插件仓库根目录）：
 *   node test/desktop-host-e2e.mjs [--plugin <dir>] [--profile <name>] [--port <n>] [--keep]
 *
 * 隔离性：默认把插件复制到临时目录再挂载（凭据一并复制，闸门处于启用态），因此
 * 既不会改动仓库里的真实 sessions.jsonl，也不会写入用户的 profile 数据。
 * `--plugin` 指向一个已准备好的沙箱目录时可直接使用它。
 *
 * 环境变量：DSH_DESKTOP_ROOT —— 桌面端安装目录，默认 `D:\App\DeepSeek Harness`。
 */

import { spawn, spawnSync } from 'node:child_process'
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import net from 'node:net'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..')

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback
}

const DESKTOP_ROOT = process.env.DSH_DESKTOP_ROOT || 'D:\\App\\DeepSeek Harness'
const ASAR_DSH = join(DESKTOP_ROOT, 'resources', 'app.asar', 'dsh')
const EXE = join(DESKTOP_ROOT, 'DeepSeek Harness.exe')
const CLI_BIN = join(ASAR_DSH, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const DSH_HOME = join(homedir(), '.dsh')
const PROFILE_NAME = argValue('--profile', 'dsh-webui-auth-e2e')
const PROFILE = join(DSH_HOME, 'profiles', PROFILE_NAME)
const PORT = Number(argValue('--port', '19399'))
const KEEP = process.argv.includes('--keep')
const pluginArg = argValue('--plugin', repoRoot)

const results = []
function check(name, got, want) {
  const ok = got === want
  results.push({ name, ok })
  console.log((ok ? '  ok   ' : '  FAIL ') + name + '  got=' + JSON.stringify(got) + ' want=' + JSON.stringify(want))
}

/** 把插件准备成独立沙箱：复制代码 + 凭据，DATADIR 因此落在临时目录里。 */
function preparePlugin() {
  const prepared = join(pluginArg, 'node_modules') // 已经是沙箱形状就不用再复制
  if (existsSync(prepared) || process.argv.includes('--in-place')) return pluginArg
  const dir = mkdtempSync(join(tmpdir(), 'dsh-webui-auth-e2e-'))
  for (const f of ['index.js', 'package.json', 'cordis.patch.yml']) copyFileSync(join(pluginArg, f), join(dir, f))
  cpSync(join(pluginArg, 'lib'), join(dir, 'lib'), { recursive: true })
  const creds = join(pluginArg, 'dsh-webui-auth.json')
  if (existsSync(creds)) copyFileSync(creds, join(dir, 'dsh-webui-auth.json'))
  return dir
}

function setupProfile(pluginDir) {
  rmSync(PROFILE, { recursive: true, force: true })
  mkdirSync(join(PROFILE, 'node_modules'), { recursive: true })
  if (process.argv.includes('--preflight-desktop')) {
    // 预演真实桌面端 profile 的组合：复制它的组合文件，node_modules 用 junction 指过去
    // （避免复制 .pnpm / dshmarket 的体积），并把 dsh-webui-auth 加进 bundles。
    const src = join(DSH_HOME, 'profiles', 'desktop')
    const pkg = JSON.parse(readFileSync(join(src, 'package.json'), 'utf8'))
    const bundles = (pkg.dsh && pkg.dsh.profile && pkg.dsh.profile.bundles) ? pkg.dsh.profile.bundles.slice() : []
    if (!bundles.includes('dsh-webui-auth')) bundles.push('dsh-webui-auth')
    pkg.dsh = { ...(pkg.dsh || {}), profile: { ...((pkg.dsh || {}).profile || {}), bundles } }
    writeFileSync(join(PROFILE, 'package.json'), JSON.stringify(pkg, null, 2))
    for (const f of ['cordis.patch.yml', 'cordis.yml', 'pnpm-workspace.yaml']) {
      if (existsSync(join(src, f))) copyFileSync(join(src, f), join(PROFILE, f))
    }
    // node_modules：逐项 junction 到真实目录，但 dsh-webui-auth 指向沙箱副本。
    // 关键：否则插件会以真实仓库为 DATA_DIR，与正在运行的桌面端争抢 sessions.jsonl
    // （两个实例各持一份内存视图，compaction 会互相覆盖）。
    rmSync(join(PROFILE, 'node_modules'), { recursive: true, force: true })
    mkdirSync(join(PROFILE, 'node_modules'), { recursive: true })
    const realModules = join(src, 'node_modules')
    for (const entry of readdirSync(realModules)) {
      if (entry === 'dsh-webui-auth') continue
      const target = join(realModules, entry)
      let kind = 'junction'
      try { kind = statSync(target).isDirectory() ? 'junction' : 'file' } catch (e) { continue }
      try { symlinkSync(target, join(PROFILE, 'node_modules', entry), kind) } catch (e) { /* 单项失败可忽略 */ }
    }
    symlinkSync(pluginDir, join(PROFILE, 'node_modules', 'dsh-webui-auth'), 'junction')
    return
  }
  writeFileSync(join(PROFILE, 'package.json'), JSON.stringify({
    name: 'dsh-profile-' + PROFILE_NAME,
    private: true,
    dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app', 'dsh-webui-auth'] } },
    dependencies: { 'dsh-webui-auth': 'link:' + pluginDir },
  }, null, 2))
  writeFileSync(join(PROFILE, 'cordis.yml'), '[]\n')
  writeFileSync(join(PROFILE, 'cordis.patch.yml'), '# dsh-webui-auth e2e probe profile\n[]\n')
  symlinkSync(pluginDir, join(PROFILE, 'node_modules', 'dsh-webui-auth'), 'junction')
}

function killTree(pid) {
  if (!pid) return
  try { spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' }) } catch (e) { /* ignore */ }
}

function wsProbe(port, cookie) {
  return new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(
        'GET /api/remote.mux HTTP/1.1\r\n' +
        'Host: 127.0.0.1:' + port + '\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
        'Sec-WebSocket-Version: 13\r\n' +
        'Origin: http://127.0.0.1:' + port + '\r\n' +
        'Sec-Fetch-Site: same-origin\r\n' +
        (cookie ? 'Cookie: ' + cookie + '\r\n' : '') +
        '\r\n')
    })
    let buf = ''
    let settled = false
    const done = () => { if (settled) return; settled = true; try { socket.destroy() } catch (e) {} resolve(buf.split('\r\n')[0] || '(no response)') }
    socket.on('data', (c) => { buf += c.toString('utf8'); if (buf.includes('\r\n')) done() })
    socket.on('error', (e) => { if (!settled) { settled = true; resolve('ERROR ' + e.message) } })
    socket.setTimeout(5000, done)
  })
}

// CLI_BIN 位于 app.asar 内部：普通 Node 无法 stat asar 内路径，因此只校验外层文件。
for (const p of [EXE, join(DESKTOP_ROOT, 'resources', 'app.asar')]) {
  if (!existsSync(p)) {
    console.error('找不到桌面端运行时：' + p + '\n请用 DSH_DESKTOP_ROOT 指定安装目录。')
    process.exit(2)
  }
}

const sandboxPlugin = preparePlugin()
setupProfile(sandboxPlugin)
console.log('plugin: ' + sandboxPlugin + '\nprofile: ' + PROFILE + '\nport: ' + PORT + '\n')

const child = spawn(EXE, [
  '--expose-internals', CLI_BIN, '--profile', PROFILE_NAME, '--port', String(PORT), '--no-open',
], {
  cwd: PROFILE,
  env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  stdio: ['ignore', 'pipe', 'pipe'],
})

let stdout = ''
let stderr = ''
child.stdout.setEncoding('utf8')
child.stderr.setEncoding('utf8')
child.stdout.on('data', (d) => { stdout += d; process.stdout.write('[web] ' + d) })
child.stderr.on('data', (d) => { stderr += d; process.stdout.write('[web:err] ' + d) })

let finished = false
function finish(code) {
  if (finished) return
  finished = true
  killTree(child.pid)
  if (!KEEP && sandboxPlugin !== pluginArg) { try { rmSync(sandboxPlugin, { recursive: true, force: true }) } catch (e) { /* ignore */ } }
  const failed = results.filter((r) => !r.ok).length
  console.log('\n' + (results.length - failed) + ' passed, ' + failed + ' failed')
  // 宿主子进程可能还握着目录句柄，删除要重试几次，否则会留下一个孤儿 profile。
  let attempts = 0
  const cleanup = () => {
    try { rmSync(PROFILE, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    if (existsSync(PROFILE) && attempts < 6) { attempts++; setTimeout(cleanup, 400); return }
    if (existsSync(PROFILE)) console.log('提示：未能删除临时 profile ' + PROFILE)
    process.exit(code)
  }
  setTimeout(cleanup, 600)
}

const urlLine = new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('90s 内没有出现 "dsh web:" 行\nstdout:\n' + stdout.slice(-1500) + '\nstderr:\n' + stderr.slice(-1500))), 90000)
  const poll = setInterval(() => {
    const m = /dsh web: (\S+)/.exec(stdout)
    if (m) { clearInterval(poll); clearTimeout(timer); resolve(m[1]) }
  }, 250)
  child.on('close', (code) => { clearInterval(poll); clearTimeout(timer); reject(new Error('host 提前退出，code=' + code + '\n' + stderr.slice(-1500))) })
})

try {
  const printed = await urlLine
  const url = new URL(printed)
  const origin = url.origin
  console.log('host url: ' + printed + '\n')

  // ① 桌面端 shell 启动握手
  const hs = await fetch(printed, { redirect: 'manual' })
  const setCookie = hs.headers.get('set-cookie')
  await hs.body?.cancel()
  check('① authenticateWebHost 拿到 303', hs.status, 303)
  check('① 303 携带 set-cookie', setCookie !== null, true)
  const cookie = setCookie === null ? null : (setCookie.indexOf(';') < 0 ? setCookie : setCookie.slice(0, setCookie.indexOf(';')))

  // ② connectDesktopWelcome：带核心凭据的 RPC
  const rpc = await fetch(origin + '/api/settings/describe', {
    method: 'POST',
    redirect: 'error',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify({ type: 'client-request', rpcId: 'e2e-1', method: 'settings/describe', payload: { args: {} } }),
  })
  const rpcBody = await rpc.text()
  let envelopeOk = false
  try { const env = JSON.parse(rpcBody); envelopeOk = env && env.type === 'server-response' && env.result && env.result.ok === true } catch (e) { /* not json */ }
  check('② 带核心凭据的 /api RPC 未被 401', rpc.status, 200)
  check('② 返回核心 RPC 成功信封', envelopeOk, true)

  // ③ 渲染器转发 /plugins
  const bundle = await fetch(origin + '/plugins/dsh-webui-auth/client.js', { headers: cookie ? { cookie } : {} })
  await bundle.body?.cancel()
  check('③ 带核心凭据的 /plugins 未被插件 401', bundle.status === 401 ? 'plugin 401' : 'admitted', 'admitted')
  // 桌面端锁：解锁令牌校验端点必须在真宿主上存在并拒绝伪造令牌
  const ds = await fetch(origin + '/dsh-webui-auth/desktop-session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: 'f'.repeat(48) }),
  })
  const dsBody = await ds.text()
  let dsJson = null
  try { dsJson = JSON.parse(dsBody) } catch (e) { /* not json */ }
  check('③ 桌面端锁校验端点存在且拒绝伪造令牌', Boolean(dsJson && dsJson.ok === false), true)
  // /plugins/events 是顶层 exact 路由（路由表 exact 优先于 prefix），必须同样被闸门覆盖
  const anonEvents = await fetch(origin + '/plugins/events', { headers: { 'user-agent': 'Mozilla/5.0 probe' } })
  await anonEvents.body?.cancel()
  check('③ 匿名 /plugins/events 被闸门拦下（exact 路由不被旁路）', anonEvents.status, 401)
  const authEvents = await fetch(origin + '/plugins/events', { headers: cookie ? { cookie } : {} })
  await authEvents.body?.cancel()
  check('③ 带核心凭据的 /plugins/events 未被插件 401', authEvents.status === 401 ? 'plugin 401' : 'admitted', 'admitted')

  // ④ WebSocket 升级
  const wsLine = await wsProbe(PORT, cookie)
  console.log('    ws first line: ' + wsLine)
  check('④ 带核心凭据的 WS 升级未被插件拒绝', wsLine.includes('401'), false)

  // ⑤ 对照组：口令闸门
  const anonApi = await fetch(origin + '/api/settings/describe', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 probe' },
    body: '{}',
  })
  await anonApi.body?.cancel()
  check('⑤ 无凭据 /api 仍 401', anonApi.status, 401)

  const anonDoc = await fetch(origin + '/', {
    redirect: 'manual',
    headers: { 'user-agent': 'Mozilla/5.0 probe', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none' },
  })
  const loc = anonDoc.headers.get('location')
  await anonDoc.body?.cancel()
  check('⑤ 无凭据文档请求仍跳登录页', loc, '/dsh-webui-auth/login')

  const bad = await fetch(origin + '/?token=definitely-not-the-token', { redirect: 'manual' })
  const badLoc = bad.headers.get('location')
  await bad.body?.cancel()
  check('⑤ 错误 token 仍跳登录页', badLoc, '/dsh-webui-auth/login')

  finish(results.every((r) => r.ok) ? 0 : 1)
} catch (e) {
  console.error('probe error: ' + (e && e.message ? e.message : String(e)))
  finish(2)
}
