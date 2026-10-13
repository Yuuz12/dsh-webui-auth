/**
 * 桌面端锁（C8）客户端存储层回归测试。
 *
 * 覆盖的是「会话有效期 → 存在哪里」这条语义，也就是用户直接感受到的行为：
 *   · 有效期 = 浏览器会话（ttl = 0）→ sessionStorage：关掉/重启桌面端后必须重新输口令；
 *   · 有效期 = 1 小时 / 1 天 / 3 天（ttl > 0）→ localStorage + 到期时间：到期前免输。
 * 另外验证过期清理、脏数据忽略、以及 localStorage 优先于 sessionStorage。
 *
 * lib/client.js 是 `window.__ModuleLoader__.load({factory})` 形式的浏览器模块，所以这里给一个
 * 最小 window/document/location 垫片再取 factory —— 不需要真实 DOM（锁的 DOM 部分不在这里测）。
 *
 * 运行：node test/desktop-lock-client.test.mjs
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

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

function makeStorage() {
  const map = new Map()
  return {
    get length() { return map.size },
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(String(k), String(v)) },
    removeItem: (k) => { map.delete(k) },
    clear: () => map.clear(),
    __map: map,
  }
}

const localStorage = makeStorage()
const sessionStorage = makeStorage()
const loaded = {}

globalThis.window = {
  __ModuleLoader__: { load: (mod) => { loaded.id = mod.id; loaded.factory = mod.factory } },
  localStorage,
  sessionStorage,
}
globalThis.location = { protocol: 'dsh-app:', href: 'dsh-app://app/' }
globalThis.document = {
  createElement: () => ({ setAttribute() {}, style: {}, appendChild() {}, removeChild() {} }),
  head: { appendChild() {} },
  body: { appendChild() {} },
}

const here = dirname(fileURLToPath(import.meta.url))
const source = readFileSync(join(here, '..', 'lib', 'client.js'), 'utf8')
// 直接在全局作用域求值：模块体只依赖上面这些垫片（factory 里的 react 到 apply 时才用）
await import('data:text/javascript;base64,' + Buffer.from(source, 'utf8').toString('base64'))
  .catch(async () => { await import(pathToFileURL(join(here, '..', 'lib', 'client.js')).href) })

eq('模块被 __ModuleLoader__ 接管', typeof loaded.factory, 'function')
const mod = loaded.factory(() => ({}))
const lock = mod.__desktopLockInternals
eq('导出了桌面端锁内部接口', Boolean(lock && lock.readUnlock && lock.writeUnlock && lock.clearUnlock), true)

const TOKEN = 'a'.repeat(48)
const TOKEN2 = 'b'.repeat(48)

console.log('\n— 有效期语义 —')
lock.writeUnlock(TOKEN, 0)
eq('ttl=0（浏览器会话）写入 sessionStorage', sessionStorage.getItem(lock.UNLOCK_KEY) !== null, true)
eq('ttl=0 不写 localStorage（重启桌面端必须重新输口令）', localStorage.getItem(lock.UNLOCK_KEY), null)

lock.clearUnlock()
lock.writeUnlock(TOKEN, 12)
eq('ttl=12 写入 localStorage（跨重启免输）', localStorage.getItem(lock.UNLOCK_KEY) !== null, true)
eq('ttl=12 不写 sessionStorage', sessionStorage.getItem(lock.UNLOCK_KEY), null)
const stored = JSON.parse(localStorage.getItem(lock.UNLOCK_KEY))
eq('存了到期时间', typeof stored.expiresAt === 'number' && stored.expiresAt > Date.now(), true)
eq('读回来是同一个令牌', lock.readUnlock().token, TOKEN)

console.log('\n— 过期与脏数据 —')
localStorage.setItem(lock.UNLOCK_KEY, JSON.stringify({ token: TOKEN, ttl: 12, expiresAt: Date.now() - 1000 }))
eq('过期令牌不再解锁', lock.readUnlock(), null)
eq('过期条目被顺手清掉', localStorage.getItem(lock.UNLOCK_KEY), null)

localStorage.setItem(lock.UNLOCK_KEY, JSON.stringify({ token: 'not-a-token', ttl: 12, expiresAt: 0 }))
eq('畸形令牌被忽略', lock.readUnlock(), null)

localStorage.setItem(lock.UNLOCK_KEY, '{oops')
eq('损坏 JSON 被忽略', lock.readUnlock(), null)

console.log('\n— 清除与优先级 —')
lock.clearUnlock()
sessionStorage.setItem(lock.UNLOCK_KEY, JSON.stringify({ token: TOKEN2, ttl: 0, expiresAt: 0 }))
eq('只读 sessionStorage 时也能解锁', lock.readUnlock().token, TOKEN2)
localStorage.setItem(lock.UNLOCK_KEY, JSON.stringify({ token: TOKEN, ttl: 72, expiresAt: Date.now() + 3600_000 }))
eq('localStorage（长期会话）优先于 sessionStorage', lock.readUnlock().token, TOKEN)
lock.clearUnlock()
eq('clearUnlock 清空两者', lock.readUnlock(), null)
eq('  · localStorage', localStorage.getItem(lock.UNLOCK_KEY), null)
eq('  · sessionStorage', sessionStorage.getItem(lock.UNLOCK_KEY), null)

console.log('\n— 存储不可用时不得抛错 —')
const savedWindow = globalThis.window
globalThis.window = { __ModuleLoader__: savedWindow.__ModuleLoader__, get localStorage() { throw new Error('blocked') }, get sessionStorage() { throw new Error('blocked') } }
let threw = false
try {
  lock.writeUnlock(TOKEN, 12)
  const got = lock.readUnlock()
  lock.clearUnlock()
  if (got === null || got.token !== TOKEN) threw = true   // 内存兜底：同一次运行内仍可解锁
} catch (e) { threw = true }
eq('存储被禁用时走内存兜底且不抛错', threw, false)
globalThis.window = savedWindow

console.log('\n' + pass + ' passed, ' + fail + ' failed')
process.exit(fail === 0 ? 0 : 1)
