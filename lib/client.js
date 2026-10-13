window.__ModuleLoader__.load({
	id: 'dsh-webui-auth',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		let react = require('react');

		const inject = ['slots'];

		const CSS = [
			'.wua-section { display: flex; flex-direction: column; gap: 14px; max-width: 560px; padding: 4px 2px; }',
			'.wua-intro { margin: 0; font-size: 13px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-row { display: flex; flex-direction: column; gap: 5px; }',
			'.wua-label { font-size: 12px; color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-input { box-sizing: border-box; width: 100%; padding: 7px 9px; font-size: 13px; color: var(--dsw-alias-label-primary, #222); background: var(--dsw-alias-bg-layer-2, #fff); border: 1px solid var(--dsw-alias-border-l1, #ccc); border-radius: 4px; outline: none; }',
			'.wua-input:focus { border-color: var(--dsw-alias-brand-primary, #4a7cf7); }',
			'/* 深色模式下浏览器自动填充会把输入框刷成白色/黄色：inset 大阴影 + text-fill-color 回压为当前主题输入底色 */',
			'.wua-input:-webkit-autofill, .wua-input:-webkit-autofill:hover, .wua-input:-webkit-autofill:focus { -webkit-text-fill-color: var(--dsw-alias-label-primary, #222); -webkit-box-shadow: 0 0 0 1000px var(--dsw-alias-bg-layer-2, #fff) inset; box-shadow: 0 0 0 1000px var(--dsw-alias-bg-layer-2, #fff) inset; caret-color: var(--dsw-alias-label-primary, #222); transition: background-color 999999s ease-in-out 0s; }',
			'.wua-input::placeholder { color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-select { box-sizing: border-box; width: 100%; padding: 7px 9px; font-size: 13px; color: var(--dsw-alias-label-primary, #222); background: var(--dsw-alias-bg-layer-2, #fff); border: 1px solid var(--dsw-alias-border-l1, #ccc); border-radius: 4px; outline: none; }',
			'.wua-btn { align-self: flex-start; padding: 7px 18px; font-size: 13px; cursor: pointer; color: var(--dsw-alias-label-primary, #222); background: var(--dsw-alias-bg-layer-1, #fff); border: 1px solid var(--dsw-alias-border-l2, #999); border-radius: 4px; }',
			'.wua-btn:hover:not(:disabled) { border-color: var(--dsw-alias-label-secondary, #555); }',
			'.wua-btn:disabled { opacity: 0.55; cursor: default; }',
			'.wua-btn.ghost { background: transparent; border-color: var(--dsw-alias-border-l1, #ccc); }',
			'.wua-btnrow { display: flex; flex-wrap: wrap; gap: 8px; }',
			'.wua-msg { margin: 0; font-size: 12px; color: var(--dsw-alias-state-success-primary, #1a7f37); }',
			'.wua-err { margin: 0; font-size: 12px; color: var(--dsw-alias-state-error-primary, #d1242f); }',
			'.wua-warn { margin: 0; padding: 10px 12px; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-state-warn-primary, #9a6700); background: color-mix(in srgb, var(--dsw-alias-state-warn-primary, #9a6700) 10%, transparent); border: 1px solid var(--dsw-alias-state-warn-primary, #9a6700); border-radius: 4px; }',
			'.wua-hint { margin: 0; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888); border-top: 1px solid var(--dsw-alias-border-l1, #e5e5e5); padding-top: 10px; }',
			'.wua-audit { display: flex; flex-direction: column; gap: 4px; }',
			'.wua-audit-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 3px 10px; font-size: 12px; line-height: 1.6; }',
			'.wua-audit-time { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-audit-event { color: var(--dsw-alias-label-primary, #222); }',
			'.wua-audit-user { color: var(--dsw-alias-state-business-primary, #4176e6); }',
			'.wua-audit-ip { color: var(--dsw-alias-label-tertiary, #999); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }',
			/* ---- 桌面端锁（C8）：一层盖住整个窗口的解锁界面 ---- */
			'.wua-lock { position: fixed; inset: 0; z-index: 2147483000; display: flex; align-items: center; justify-content: center; padding: 24px; background: color-mix(in srgb, var(--dsw-alias-bg-base, #111) 82%, transparent); backdrop-filter: blur(6px); }',
			'.wua-lock-card { box-sizing: border-box; width: 100%; max-width: 380px; display: flex; flex-direction: column; gap: 12px; padding: 24px; background: var(--dsw-alias-bg-layer-1, #fff); border: 1px solid var(--dsw-alias-border-l1, #ddd); border-radius: 10px; box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28); }',
			'.wua-lock-title { margin: 0; font-size: 16px; font-weight: 600; color: var(--dsw-alias-label-primary, #222); }',
			'.wua-lock-sub { margin: 0; font-size: 12px; line-height: 1.6; color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-lock-slot { display: flex; flex-direction: column; gap: 5px; }',
			'.wua-lock-slot > span { font-size: 12px; color: var(--dsw-alias-label-secondary, #888); }',
			'.wua-lock-err { min-height: 16px; margin: 0; font-size: 12px; color: var(--dsw-alias-state-error-primary, #d1242f); }',
			'.wua-lock-note { margin: 0; font-size: 11px; line-height: 1.6; color: var(--dsw-alias-label-tertiary, #999); border-top: 1px solid var(--dsw-alias-border-l1, #eee); padding-top: 10px; }',
		].join('\n');

		// ---------------- 桌面端锁的存储层（C8，模块作用域，便于单测） ----------------
		//
		// 桌面端窗口的每个请求都由 shell 代理转发，而它 dispatch 前会 **替换** Cookie 头
		// （forwardWebRequest: delete('cookie') → set('cookie', hostCookie)），响应里的
		// set-cookie 也被丢掉（WITHHELD_RESPONSE_HEADERS）。所以插件会话 Cookie 永远进不了
		// 渲染器，服务端也不可能对桌面端做口令判定——传输层始终由 DSH 自身（核心 Cookie）认证。
		// 这里做的是 UI 级锁：解锁令牌由客户端自己保存，有效期"浏览器会话"→ sessionStorage
		// （应用一关就没，重启桌面端要重新输口令），1 小时/1 天/3 天 → localStorage + 到期时间。
		const LOCK_ID = 'dsh-wua-lock';
		const UNLOCK_KEY = 'dsh-webui-auth.unlock';
		const TOKEN_RE = /^[0-9a-f]{48}$/;
		const LOCK_FAILOPEN_MS = 8000;
		const LOGIN_ERRORS = {
			'invalid': '账号或密码不正确。',
			'rate-limited': '尝试过于频繁，请稍后再试。',
			'not-configured': '尚未配置账号密码。',
		};

		let unlockMemory = null;
		let unlockMemoryOnly = false;   // 存储不可用/写失败时才允许用内存兜底

		function safeStorage(kind) {
			try {
				const store = window[kind];
				store.setItem('dsh-webui-auth.probe', '1');
				store.removeItem('dsh-webui-auth.probe');
				return store;
			} catch (e) {
				return null;
			}
		}

		/**
		 * 读已保存的解锁令牌：localStorage（定期有效期）优先，其次 sessionStorage（浏览器会话）。
		 * 存储里明确写着"过期/畸形/损坏"就是不解锁——只有在存储根本不可用（或写入失败）时，
		 * 才退回本次运行的内存状态。
		 */
		function readUnlock() {
			for (const store of [safeStorage('localStorage'), safeStorage('sessionStorage')]) {
				if (store === null) continue;
				try {
					const raw = store.getItem(UNLOCK_KEY);
					if (!raw) continue;
					const parsed = JSON.parse(raw);
					if (!parsed || !TOKEN_RE.test(String(parsed.token || ''))) continue;
					if (typeof parsed.expiresAt === 'number' && parsed.expiresAt > 0 && parsed.expiresAt <= Date.now()) {
						store.removeItem(UNLOCK_KEY);
						continue;
					}
					return { token: String(parsed.token) };
				} catch (e) { /* 脏数据忽略 */ }
			}
			if (unlockMemoryOnly && unlockMemory !== null) return { token: unlockMemory.token };
			return null;
		}

		/** ttl > 0 存 localStorage（跨重启，带到期时间）；ttl = 0 存 sessionStorage（本次运行有效）。 */
		function writeUnlock(token, ttl) {
			unlockMemory = { token };
			unlockMemoryOnly = false;
			const store = safeStorage(ttl > 0 ? 'localStorage' : 'sessionStorage');
			if (store === null) {
				unlockMemoryOnly = true;
				return;
			}
			try {
				store.setItem(UNLOCK_KEY, JSON.stringify({
					token,
					ttl,
					expiresAt: ttl > 0 ? Date.now() + ttl * 3600 * 1000 : 0,
				}));
			} catch (e) {
				unlockMemoryOnly = true;   // 存不下就退化为"本次运行内有效"
			}
		}

		function clearUnlock() {
			unlockMemory = null;
			unlockMemoryOnly = false;
			for (const store of [safeStorage('localStorage'), safeStorage('sessionStorage')]) {
				if (store === null) continue;
				try { store.removeItem(UNLOCK_KEY); } catch (e) { /* ignore */ }
			}
		}

		function apply(ctx) {
			const styleEl = document.createElement('style');
			styleEl.setAttribute('data-plugin', 'dsh-webui-auth');
			styleEl.textContent = CSS;
			document.head.appendChild(styleEl);
			ctx.effect(() => () => {
				if (styleEl.parentNode !== null) styleEl.parentNode.removeChild(styleEl);
			}, 'dsh-webui-auth: styles');

			// ---------------- 桌面端锁（C8）：DOM 与流程 ----------------
			// 任何一步异常都会在 8 秒内自动放行——这把锁挡的是"人"，绝不能把桌面端锁死。
			let lockEl = null;
			let lockParts = null;
			let revalidateTimer = null;

			// 锁内专用请求：不走 api()，避免 401 触发 location.href = '/' 造成刷新循环；
			// 带 10 秒超时，避免请求悬挂时界面永远停在"解锁中…"。
			function lockFetch(path, body) {
				const opts = body === undefined
					? {}
					: { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
				const request = fetch(path, opts)
					.then((r) => r.json().catch(() => null))
					.catch(() => null);
				const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 10000));
				return Promise.race([request, timeout]);
			}

			function buildLock() {
				const el = document.createElement('div');
				el.id = LOCK_ID;
				el.className = 'wua-lock';
				el.innerHTML = [
					'<form class="wua-lock-card">',
					'<h1 class="wua-lock-title">DSH 桌面端已锁定</h1>',
					'<p class="wua-lock-sub">输入账号密码解锁。桌面端的传输层由 DSH 自身认证，这层锁用于挡住界面。</p>',
					'<label class="wua-lock-slot"><span>用户名</span><input class="wua-input" id="wua-lock-user" type="text" autocomplete="username" spellcheck="false"></label>',
					'<label class="wua-lock-slot"><span>密码</span><input class="wua-input" id="wua-lock-pass" type="password" autocomplete="current-password"></label>',
					'<p class="wua-lock-err"></p>',
					'<button class="wua-btn" id="wua-lock-submit" type="submit">解锁</button>',
					'<p class="wua-lock-note">忘记密码：删除插件数据目录的 <code>dsh-webui-auth.json</code> 后重启 DSH（认证会自动关闭），见 README「忘记密码」。</p>',
					'</form>',
				].join('');
				document.body.appendChild(el);
				const form = el.querySelector('form');
				const user = el.querySelector('#wua-lock-user');
				const pass = el.querySelector('#wua-lock-pass');
				const err = el.querySelector('.wua-lock-err');
				const submit = el.querySelector('#wua-lock-submit');
				form.addEventListener('submit', (event) => {
					event.preventDefault();
					submitUnlock(user.value.trim(), pass.value);
				});
				lockEl = el;
				lockParts = {
					user,
					pass,
					err,
					submit,
					setMessage(text) { err.textContent = text || ''; },
					setBusy(busy) {
						submit.disabled = Boolean(busy);
						submit.textContent = busy ? '解锁中…' : '解锁';
					},
				};
				setTimeout(() => { try { (user.value ? pass : user).focus(); } catch (e) { /* ignore */ } }, 30);
			}

			function lockNow(message) {
				if (revalidateTimer !== null) { clearInterval(revalidateTimer); revalidateTimer = null; }
				if (lockEl === null) buildLock();
				if (lockParts !== null) {
					lockParts.setBusy(false);
					lockParts.setMessage(message || null);
				}
			}

			function unlockNow() {
				if (lockEl !== null && lockEl.parentNode !== null) lockEl.parentNode.removeChild(lockEl);
				lockEl = null;
				lockParts = null;
			}

			/**
			 * 校验解锁令牌：'valid' / 'invalid' / 'unknown'。
			 * 区分后两者很重要——网络抖动（unknown）不该把正在用的人锁在门外，
			 * 只有服务端明确说"这个令牌不认"（invalid）才重新上锁。
			 */
			async function validateUnlock(token) {
				const r = await lockFetch('/dsh-webui-auth/desktop-session', { token });
				if (r === null) return 'unknown';
				return r.ok === true ? 'valid' : 'invalid';
			}

			function startRevalidate() {
				if (revalidateTimer !== null) return;
				revalidateTimer = setInterval(async () => {
					if (lockEl === null) return;              // 已上锁：等待用户输入
					const stored = readUnlock();
					if (stored === null) return;
					if (await validateUnlock(stored.token) === 'invalid') {
						clearUnlock();
						lockNow('登录状态已过期，请重新输入口令。');
					}
				}, 60000);
				ctx.effect(() => () => { if (revalidateTimer !== null) clearInterval(revalidateTimer); }, 'dsh-webui-auth: desktop lock timer');
			}

			async function submitUnlock(username, password) {
				if (lockParts === null) return;
				lockParts.setBusy(true);
				lockParts.setMessage(null);
				const r = await lockFetch('/dsh-webui-auth/login', { username, password });
				if (r && r.ok === true) {
					const token = typeof r.desktopToken === 'string' ? r.desktopToken : '';
					if (TOKEN_RE.test(token)) writeUnlock(token, typeof r.desktopTtl === 'number' ? r.desktopTtl : 0);
					else clearUnlock();   // 服务端没发令牌（旧核心）：本次解锁只在本页内存里有效
					unlockNow();
					startRevalidate();
					return;
				}
				if (r && r.ok === false && r.error === 'not-configured') { unlockNow(); return; }
				lockParts.setBusy(false);
				lockParts.setMessage(LOGIN_ERRORS[r && r.error] || '解锁失败：无法连接认证服务。');
			}

			// 桌面端锁只认桌面端载体：浏览器由传输层登录页负责，客户端不插手。
			// isDesktop 用 location.protocol 同步判定，保证遮罩在应用渲染之前就盖上。
			const desktopLock = {
				isDesktop: location.protocol === 'dsh-app:',
				// 退出登录：清掉本地解锁并重新上锁（服务端会话由调用方吊销）
				relock(message) { clearUnlock(); lockNow(message || null); },
				token() { const stored = readUnlock(); return stored === null ? null : stored.token; },
			};

			async function armDesktopLock() {
				if (!desktopLock.isDesktop) return;
				lockNow(null);
				// 兜底：8 秒内没能证明"不该锁"就放行，绝不把桌面端锁死
				const failOpen = setTimeout(() => { if (lockEl !== null) unlockNow(); }, LOCK_FAILOPEN_MS);
				const status = await lockFetch('/dsh-webui-auth/status');
				clearTimeout(failOpen);
				if (!status) { unlockNow(); return; }              // 读不到状态：放行
				if (status.enabled !== true) { unlockNow(); return; }  // 未启用认证：不锁
				if (lockParts !== null && typeof status.username === 'string') lockParts.user.value = status.username;
				const stored = readUnlock();
				if (stored !== null && await validateUnlock(stored.token) === 'valid') {
					unlockNow();
					startRevalidate();
					return;
				}
				clearUnlock();
				lockNow(null);   // 保持上锁，等待口令
			}

			// ---------------- 同源 HTTP API（会话 cookie 由浏览器自动携带） ----------------
			function api(path, body) {
				const opts = body === undefined
					? {}
					: { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
				return fetch(path, opts).then((r) => {
					if (r.status === 401) {
						// 会话过期或无效：跳回首页，由 HTTP 层重定向到登录页
						location.href = '/';
						return { ok: false, error: 'unauthorized' };
					}
					return r.json();
				});
			}

			// ---------------- 设置页（settings.section） ----------------
			let loadedOnce = false;
			function AuthSettings() {
				const [status, setStatus] = react.useState(null);
				const [username, setUsername] = react.useState('');
				const [password, setPassword] = react.useState('');
				const [confirm, setConfirm] = react.useState('');
				const [current, setCurrent] = react.useState('');
				const [ttl, setTtl] = react.useState('12');
				const [msg, setMsg] = react.useState(null);
				const [busy, setBusy] = react.useState(false);
				const [audit, setAudit] = react.useState(null);

				react.useEffect(() => {
					let alive = true;
					const load = () => api('/dsh-webui-auth/status').then((s) => {
						if (!alive) return;
						if (!s || s.error) return;
						setStatus(s);
						setTtl(String(typeof s.ttl === 'number' ? s.ttl : 12));
						if (!loadedOnce) {
							loadedOnce = true;
							setUsername(s.username || '');
						}
					});
					load();
					api('/dsh-webui-auth/audit?limit=8').then((r) => {
						if (!alive) return;
						if (r && r.ok && Array.isArray(r.entries)) setAudit(r.entries);
					}).catch(() => { /* 审计不可用时静默 */ });
					return () => {
						alive = false;
					};
				}, []);

				// 与服务端 passwordStrength 一致的同步校验
				const SPECIAL_CHARS = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~]/;
				function checkPassword(p) {
					if (!p || p.length < 8) return { ok: false, text: '密码至少需要 8 位' };
					if (!/[a-z]/.test(p)) return { ok: false, text: '密码必须包含小写字母' };
					if (!/[A-Z]/.test(p)) return { ok: false, text: '密码必须包含大写字母' };
					if (!/[0-9]/.test(p)) return { ok: false, text: '密码必须包含数字' };
					if (!SPECIAL_CHARS.test(p)) return { ok: false, text: '密码必须包含特殊符号（如 !@#$%^&*）' };
					return { ok: true, text: '' };
				}

				const onSave = () => {
					if (busy) return;
					const name = username.trim();
					// 与服务端 usernameError 一致的用户名约束
					if (!/^[A-Za-z0-9_-]{3,32}$/.test(name)) {
						setMsg({ kind: 'err', text: '用户名需为 3-32 位字母、数字、下划线或连字符' });
						return;
					}
					if (!(enabled && !password)) {
						const st = checkPassword(password);
						if (!st.ok) {
							setMsg({ kind: 'err', text: st.text });
							return;
						}
					}
					if (password !== confirm) {
						setMsg({ kind: 'err', text: '两次输入的密码不一致' });
						return;
					}
					if (enabled && !current) {
						setMsg({ kind: 'err', text: '修改认证信息需要输入当前密码' });
						return;
					}
					setBusy(true);
					setMsg(null);
					api('/dsh-webui-auth/configure', { username: name, password, current, ttl: Number(ttl) }).then((r) => {
						setBusy(false);
						if (r && r.ok) {
							if (enabled) {
								setMsg({ kind: 'ok', text: '已保存。其他已登录的设备/浏览器会话已全部吊销，当前会话保持有效。' });
							} else {
								setMsg({ kind: 'ok', text: '已保存并启用认证，当前浏览器已登录。' });
							}
							setPassword('');
							setConfirm('');
							setCurrent('');
							api('/dsh-webui-auth/status').then((s) => {
								if (s && !s.error) setStatus(s);
							});
						} else if (r && r.error === 'current-invalid') {
							setMsg({ kind: 'err', text: '当前密码不正确' });
						} else if (r && r.error === 'weak-password') {
							setMsg({ kind: 'err', text: '密码强度不足：至少 8 位，需包含大小写字母、数字和特殊符号' });
						} else if (r && r.error === 'username-invalid') {
							setMsg({ kind: 'err', text: '用户名需为 3-32 位字母、数字、下划线或连字符' });
						} else if (r && r.error === 'legacy-hash') {
							setMsg({ kind: 'err', text: '当前凭据为旧版哈希（0.2.0 起仅支持 scrypt），必须填写新密码才能保存' });
						} else if (r && typeof r.error === 'string') {
							// 服务端 500/未知错误：展示真实信息便于排查
							setMsg({ kind: 'err', text: '保存失败：' + r.error });
						} else {
							setMsg({ kind: 'err', text: '保存失败，请检查输入' });
						}
					}).catch(() => {
						setBusy(false);
						setMsg({ kind: 'err', text: '保存失败：无法连接认证服务' });
					});
				};

				const onDisable = () => {
					if (busy) return;
					if (!current) {
						setMsg({ kind: 'err', text: '请输入当前密码以禁用认证' });
						return;
					}
					setBusy(true);
					setMsg(null);
					api('/dsh-webui-auth/disable', { current }).then((r) => {
						setBusy(false);
						if (r && r.ok) {
							setMsg({ kind: 'ok', text: '已禁用认证，所有会话已注销。刷新页面后不再要求登录。' });
							setCurrent('');
							api('/dsh-webui-auth/status').then((s) => {
								if (s && !s.error) setStatus(s);
							});
						} else {
							setMsg({ kind: 'err', text: '当前密码不正确' });
						}
					}).catch(() => {
						setBusy(false);
						setMsg({ kind: 'err', text: '操作失败：无法连接认证服务' });
					});
				};

				const onLogout = () => {
					if (busy) return;
					setBusy(true);
					// 桌面端：带上解锁令牌，让服务端真正吊销会话，然后重新上锁
					const body = hostCarrier ? { token: desktopLock.token() } : {};
					api('/dsh-webui-auth/logout', body).then(() => {
						if (hostCarrier) {
							desktopLock.relock('已退出登录：桌面端已锁定。');
							setBusy(false);
							setMsg({ kind: 'ok', text: '已退出登录并锁定桌面端（服务端会话已吊销）。' });
							return;
						}
						location.href = '/';
					}).catch(() => {
						setBusy(false);
						setMsg({ kind: 'err', text: '退出失败：无法连接认证服务' });
					});
				};

				const enabled = Boolean(status && status.enabled);
				const intro = status === null
					? '正在读取认证状态…'
					: (enabled
						? '认证已在 HTTP 层强制执行，当前账号：' + status.username + '。未登录的浏览器无法加载 WebUI 资源、调用接口或建立实时连接。'
						: '当前未启用认证。创建账号密码后，访问 WebUI 将强制要求登录。');

				const patchWarn = (status && status.gate && !status.gate.ok)
					? ('路由闸门不完整：' + (status.gate.problems && status.gate.problems.join('; ') || '未知原因')
						+ '。认证无法启用，直到 /api 与 WebSocket 路由可被保护。')
					: null;
				const persistNote = (status && status.sessionsPersisted === false)
					? '会话持久化写入失败（磁盘权限？）：dsh 重启后已登录设备需要重新登录。'
					: null;
				// 桌面端渲染器的请求由 shell 代理转发，而代理会替换 Cookie 头并丢弃 set-cookie，
				// 插件会话永远进不了渲染器 —— 所以桌面端用 UI 级锁，而不是传输层闸门。
				const hostCarrier = Boolean(status && status.carrier === 'host');
				const carrierNote = (status && enabled && hostCarrier)
					? '当前连接走宿主直连通道（DSH 桌面端）：传输层由 DSH 自身的启动令牌认证，插件会话 Cookie 进不了桌面端渲染器（shell 会替换 Cookie 头并丢弃 set-cookie）。因此桌面端用的是 UI 级锁——应用每次加载先要求口令，解锁状态按「会话有效期」保存：浏览器会话 = 本次运行有效（关掉/重启桌面端就要重新输入），定期有效期则到期前免输。它挡的是「人离开时看到界面」，不是传输层闸门。'
					: null;

				// 审计事件显示名
				const EVENT_LABELS = {
					login_success: '登录成功',
					login_failure: '登录失败',
					login_rate_limited: '登录被限流',
					setup_success: '初始化成功',
					setup_failure: '初始化失败',
					configure_success: '修改凭据',
					configure_failure: '修改凭据失败',
					disable_success: '禁用认证',
					disable_failure: '禁用认证失败',
					logout: '退出登录',
				};
				function fmtTime(ts) {
					if (!ts) return '?';
					const d = new Date(ts);
					if (Number.isNaN(d.getTime())) return String(ts).slice(0, 19).replace('T', ' ');
					const pad = (n) => String(n).padStart(2, '0');
					return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
				}

				return react.createElement('div', { className: 'wua-section' },
					react.createElement('p', { className: 'wua-intro' }, intro),
					patchWarn ? react.createElement('p', { className: 'wua-warn' }, patchWarn) : null,
					persistNote ? react.createElement('p', { className: 'wua-warn' }, persistNote) : null,
					carrierNote ? react.createElement('p', { className: 'wua-hint' }, carrierNote) : null,
					react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, '用户名（3-32 位字母、数字、下划线或连字符）'),
						react.createElement('input', {
							className: 'wua-input',
							type: 'text',
							value: username,
							spellCheck: false,
							onChange: (e) => setUsername(e.target.value),
						}),
					),
					react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, enabled ? '新密码（留空表示不修改）' : '密码（至少 8 位，含大小写、数字、特殊符号）'),
						react.createElement('input', {
							className: 'wua-input',
							type: 'password',
							value: password,
							onChange: (e) => setPassword(e.target.value),
						}),
					),
					react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, '确认密码'),
						react.createElement('input', {
							className: 'wua-input',
							type: 'password',
							value: confirm,
							onChange: (e) => setConfirm(e.target.value),
						}),
					),
					enabled ? react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, '当前密码（修改或禁用认证需验证）'),
						react.createElement('input', {
							className: 'wua-input',
							type: 'password',
							value: current,
							onChange: (e) => setCurrent(e.target.value),
						}),
					) : null,
					react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, '会话有效期（登录后免登录时长）'),
						react.createElement('select', {
							className: 'wua-select',
							value: ttl,
							disabled: busy || status === null,
							onChange: (e) => setTtl(e.target.value),
						},
							react.createElement('option', { key: '0', value: '0' }, '浏览器会话：关闭浏览器后失效'),
							react.createElement('option', { key: '1', value: '1' }, '1 小时'),
							react.createElement('option', { key: '12', value: '12' }, '12 小时（默认）'),
							react.createElement('option', { key: '24', value: '24' }, '1 天'),
							react.createElement('option', { key: '72', value: '72' }, '3 天'),
						),
					),
					msg ? react.createElement('div', { className: msg.kind === 'ok' ? 'wua-msg' : 'wua-err' }, msg.text) : null,
					react.createElement('div', { className: 'wua-btnrow' },
						react.createElement('button', { className: 'wua-btn', disabled: busy || status === null, onClick: onSave },
							busy ? '保存中…' : '保存账号密码'),
						enabled ? react.createElement('button', { className: 'wua-btn ghost', disabled: busy || status === null, onClick: onDisable }, '禁用认证') : null,
						enabled ? react.createElement('button', { className: 'wua-btn ghost', disabled: busy || status === null, onClick: onLogout }, hostCarrier ? '退出登录并锁定' : '退出登录') : null,
					),
					react.createElement('div', { className: 'wua-row' },
						react.createElement('label', { className: 'wua-label' }, '最近登录记录（完整审计日志可用 node index.js audit 查看）'),
						audit === null
							? react.createElement('p', { className: 'wua-intro' }, '正在读取…')
							: (audit.length === 0
								? react.createElement('p', { className: 'wua-intro' }, '暂无审计记录')
								: react.createElement('div', { className: 'wua-audit' },
									audit.map((entry, i) => react.createElement('div', { key: i, className: 'wua-audit-row' },
										react.createElement('span', { className: 'wua-audit-time' }, fmtTime(entry.ts)),
										react.createElement('span', { className: 'wua-audit-event' }, EVENT_LABELS[entry.event] || entry.event),
										entry.username ? react.createElement('span', { className: 'wua-audit-user' }, entry.username) : null,
										entry.ip ? react.createElement('span', { className: 'wua-audit-ip' }, entry.ip) : null,
									)),
								)),
					),
					react.createElement('p', { className: 'wua-hint' },
						'密码规则：至少 8 位，必须包含大写字母、小写字母、数字和特殊符号（如 !@#$%^&*）。认证在 HTTP/传输层强制执行（WebUI 资源、/api 接口、WebSocket 全部要求有效会话），会话保存在服务端并由 HttpOnly Cookie 携带，修改密码会吊销其他所有会话。凭据以 scrypt 哈希保存在插件目录的 dsh-webui-auth.json（0.2.0 起仅接受 scrypt，旧版 SHA-256 凭据需删除该文件重新创建）；忘记密码时删除该文件并重启 DSH 即可重置。'),
				);
			}

			// ---------------- 注册 ----------------
			ctx.slots.inject('settings.section', () => ctx.slots.register({
				name: 'settings.section',
				id: 'webui-auth',
				order: 30,
				label: '身份认证',
			}, AuthSettings));

			// C8：桌面端载体先上锁（浏览器完全不经过这里）
			armDesktopLock().catch(() => { if (desktopLock.isDesktop) unlockNow(); });
		}

		exports.apply = apply;
		exports.inject = inject;
		// 供 test/desktop-lock-client.test.mjs 直接验证存储层与有效期语义（浏览器里无副作用）
		exports.__desktopLockInternals = { readUnlock, writeUnlock, clearUnlock, TOKEN_RE, UNLOCK_KEY, LOCK_ID };
		return module.exports;
	}
});
