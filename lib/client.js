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
		].join('\n');

		function apply(ctx) {
			const styleEl = document.createElement('style');
			styleEl.setAttribute('data-plugin', 'dsh-webui-auth');
			styleEl.textContent = CSS;
			document.head.appendChild(styleEl);
			ctx.effect(() => () => {
				if (styleEl.parentNode !== null) styleEl.parentNode.removeChild(styleEl);
			}, 'dsh-webui-auth: styles');

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
					api('/dsh-webui-auth/logout', {}).then(() => {
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

				const patchWarn = (status && status.patch && !status.patch.ok)
					? (status.patch.reapplied
						? '检测到核心补丁缺失，已自动恢复。请重启 DSH 使认证完全生效（当前进程的 /api 与 WebSocket 尚未受保护）。'
						: '核心补丁异常：/api 与 WebSocket 未受认证保护！'
							+ (status.patch.problem
								? ' 详情：' + String(status.patch.problem).slice(0, 160) + (String(status.patch.problem).length > 160 ? '…' : '')
								: ''))
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
						enabled ? react.createElement('button', { className: 'wua-btn ghost', disabled: busy || status === null, onClick: onLogout }, '退出登录') : null,
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
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
