# dsh-webui-auth

[English](README.en.md) | 中文

DSH WebUI 身份认证插件（持久化插件）。在「设置 → 身份认证」或首次访问登录页创建账号密码后，**未认证的浏览器无法加载 WebUI 的任何资源、调用任何接口或建立任何实时连接**——认证在 HTTP/传输层强制执行，不可通过浏览器开发者工具绕过。

## 架构

认证由四层组成，全部通过**运行时包装 webServer 路由**实现，**不改动任何 DSH 核心包源码**：

| 层 | 机制 | 未认证行为 |
|---|---|---|
| WebUI 资源（index.html、/assets/*、SPA 路由） | 插件注册 `prefix ''` 兜底路由，校验会话后转交 frontend-static | 302 → 登录页 |
| 插件 bundle（/plugins/*） | 运行时包装 `/plugins` 前缀路由 handler | 401 |
| /api RPC 接口 | 运行时包装 `/api` 前缀路由 handler | 401 |
| WebSocket（/api/events.mux、/api/events.host） | 运行时包装 upgrade 路由 handler | 401 拒绝升级 |

- **不修改核心包**：dsh 升级不会覆盖补丁、不会产生「升级后 /api 裸奔」的窗口。插件每次启动对路由表重做包装，并用 2s→10s 重扫捕获晚注册路由。
- **fail-closed**：若预期路由缺失（dsh 内部结构变化导致包装不上），`setup`/`configure` 会**拒绝启用认证**，并在宿主日志与设置页同时报错——宁可不可用，不可「开了登录却裸奔 /api」。
- **反代/局域网下的特权方法**：已认证请求由插件在会话校验后以「回环形状」转交核心，使核心中**回环钉死的特权方法**（settings/credentials/agentPreset/llm.discoverModels）在反代部署下可用——会话 Cookie 闸门是比 Host 启发式更强的身份证明。
- **WebSocket 与 trustedHosts**：WS 升级握手仍受核心自身 `isTrustedApiRequest` 限制，因此**反代/局域网（非回环 Host）部署下，WS 下行需要同时在 dsh 配置中把对外域名加入 `client-connection.trustedHosts`**，否则即使已登录也会被拒绝升级。

会话为**服务端会话，持久化到磁盘**（`sessions.jsonl`，重启 DSH 不掉线，到期自动失效），由 `HttpOnly; SameSite=Lax` Cookie（`dsh_wua_session`）携带，JS 无法读取；修改密码会**吊销所有其他会话**。

## 安装

本插件是标准**组合包（bundle）**，已发布到 npm，推荐用 DSH 官方 `plugin` 命令安装；手动方式保留作备用。前提：机器上有 pnpm（Node 自带 corepack，执行 `corepack enable pnpm` 即可启用）。

### 方式一：npm 安装（推荐）

```sh
npx @deepseek-ai/dsh plugin --profile web add dsh-webui-auth
```

从 npm registry 拉取预构建代码（纯 JS 包，无 prepare 脚本、无需构建授权），加入依赖并追加到 `dsh.profile.bundles` 列表，插件行随组合包层自动插入。

### 方式二：GitHub 安装

```sh
npx @deepseek-ai/dsh plugin --profile web add github:Yuuz12/dsh-webui-auth
```

拉取仓库源码（同样直接可用，无需构建步骤）；网络不佳时优先用方式一。

### 方式三：手动（备用）

1. 将 `dsh-webui-auth` 目录放入 `profiles/web/node_modules/`
2. 在 `profiles/web/cordis.patch.yml` 的 `insert` 列表中加一行：

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

> 维护者开发模式：在本地源码目录使用 `dsh plugin --profile web add ./dsh-webui-auth`（`link:` 安装），改代码 → 重启 DSH 即生效，无需重新安装。

### 所有方式通用

安装后**无需任何核心包补丁**（无 `[dsh-webui-auth patch]` 标记、不改 `node_modules`），重启 DSH 即生效。插件启动时在宿主日志打印 `[dsh-webui-auth] started, credentials file: ...`；若路由包装不完整会打印 `ROUTE GATE INCOMPLETE`，此时认证无法启用（fail-closed）。

## 卸载

### 方式一：`dsh plugin` 命令（对应方式一安装）

1. `npx @deepseek-ai/dsh plugin --profile web remove dsh-webui-auth`（同时移除依赖与组合包层）
2. 重启 DSH

### 方式二：手动（对应方式二安装）

1. 删除插件目录 `profiles/web/node_modules/dsh-webui-auth/`
2. 从 `profiles/web/cordis.patch.yml` 移除挂载行：

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

   此步必须做，否则重启时加载器找不到插件包会报错
3. 重启 DSH

两种方式重启后认证门禁完全关闭（**无需恢复任何核心包源码**——插件从未修改核心文件）。如需清除持久化会话，删除数据目录中的 `sessions.jsonl` 即可；如曾用旧版插件，可清除浏览器 localStorage 中的 `dsh-webui-auth.session` 残留（无害）。

## 使用

- **首次启用（需 setup token）**：未配置凭据时认证自动关闭（所有请求放行），但创建管理员账号需要**本次启动生成的 setup token**——打开 WebUI → 设置 → 身份认证，或访问 `/dsh-webui-auth/login`，输入启动日志中打印的 `[dsh-webui-auth] setup token (...)`（或数据目录 `setup-token` 文件内容，0600）后创建账号密码（≥8 位，含大小写字母、数字、特殊符号）。token 每次启动重新生成、创建成功后即删除，防止「先暴露、后配置」窗口内被他人抢先注册。
- **用户名规则**：3-32 位字母、数字、下划线或连字符（新建/修改时强制；旧账号不受影响，仍可正常登录）。
- **之后**：未登录访问任意路径 → 跳转登录页；登录后按「会话有效期」免登录（浏览器会话 / 1 小时 / 12 小时（默认）/ 1 天 / 3 天），服务端按到期时间强制失效。**会话持久化到磁盘，重启 DSH 后已登录设备无需重新登录**（到期时间仍生效）。「浏览器会话」模式：活跃使用期间自动续期（30 分钟窗口），关闭浏览器即失效。
- **修改 / 禁用 / 退出**：设置 → 身份认证（均需当前密码）；修改密码会吊销其他所有已登录会话。
- **忘记密码**：删除数据目录的 `dsh-webui-auth.json` 即可——后台每分钟自动检测，最多 1 分钟内认证自动关闭（无需重启），之后用新的 setup token 重新创建账号即可。

## 数据文件位置（按安装方式区分）

凭据与安全数据存放在**运行时数据目录**：本地 link / 源码安装时为插件源码目录（卸载即清、随仓库管理）；npm / GitHub / tarball 安装时（pnpm store 只读）自动回退到 `$DSH_HOME/dsh-webui-auth/`（默认 `~/.dsh/dsh-webui-auth/`）。

目录内文件：

| 文件 | 用途 | 权限 |
|---|---|---|
| `dsh-webui-auth.json` | 凭据（scrypt 哈希，v3 格式；0.2.x 的 v2 凭据仍可正常登录校验） | — |
| `audit.jsonl` | 审计日志（IP 已假名化，见「审计日志」节） | — |
| `sessions.jsonl` | 持久化会话（重启恢复用） | 0600 |
| `audit-hmac-key` | 审计 IP 假名化的 HMAC 密钥（首次自动生成） | 0600 |
| `setup-token` | 首次初始化的 setup token（创建成功后删除） | 0600 |

插件启动时探测目录可写性并固定其一，两种安装方式的忘记密码/审计/会话路径都在各自的数据目录里。

## 审计日志

登录成功/失败/限流、初始化、修改凭据、禁用、退出等安全事件**追加写入数据目录的 `audit.jsonl`**（JSONL 格式，含时间、用户名、IP、UA、详情）。**客户端 IP 以 HMAC-SHA256 假名化存储**（形如 `hmac:5151e752|203.0.113.0/24`，附 /24（IPv4）或 /64（IPv6）网络前缀用于聚合分析），原始 IP 不落盘。两种查看方式：

- **CLI**（推荐）：运行 `node index.js audit [--limit N]`（默认最近 20 条，从模块所在路径运行即可）：
  ```sh
  node index.js audit --limit 50
  ```
- **设置页**：设置 → 身份认证 → 「最近登录记录」展示最近 8 条。

审计写入失败不影响认证主流程（仅记宿主日志）。

## 外观

登录页与「设置 → 身份认证」设置页都跟随 DSH **自带的外观设置**（设置 → 通用 → 外观：浅色 / 深色 / 跟随系统），不提供独立的外观开关。设置页运行在 WebUI 内，直接消费 DSH 的主题 token，天然随明暗切换；登录页是独立页面，由服务端读取当前外观偏好（settings `ui-theme.preference`）注入页面，并复刻 DSH 的 boot 逻辑：`跟随系统` 时按 `prefers-color-scheme` 解析、系统明暗切换时实时变化。登录页响应带 `cache-control: no-store`，外观变更后刷新即可生效。

## 升级 DSH 后的操作流程

**无需任何操作**：插件不修改核心包，dsh 升级后启动时自动重做路由包装。若包装不完整（dsh 内部结构变化），宿主日志输出 `ROUTE GATE INCOMPLETE`、设置页显示红色警告，且 `setup`/`configure` 拒绝启用认证（fail-closed）。

## 数据与安全

- 密码以 **scrypt**（Node 内置内存硬 KDF，抗 GPU/ASIC 爆破，零依赖）哈希保存在数据目录的 `dsh-webui-auth.json`，明文不落盘。凭据格式 v3（与 v2 同为 scrypt 编码，仅版本标记与字段语义不同）；0.2.x 的 v2 凭据仍可校验登录。**0.1.x 的 SHA-256 凭据自 0.2.0 起不再可校验**，需删除凭据文件后重新创建账号（见「忘记密码」）。
- 登录失败限流：**按客户端 IP** 每分钟最多 5 次——单个攻击者无法锁死其他用户（操作者）。反代场景下客户端 IP 取自 `CF-Connecting-IP` / `X-Forwarded-For` 最左侧，且**仅当对端 socket 是回环**（本机 caddy/cloudflared）时才信任代理头，远程无法伪造；校验失败时还会空跑一次 scrypt，抹平「账号不存在=响应快」的用户名枚举时序差异。
- 首次初始化需要每启动生成的 **setup token**（128-bit，打印到宿主日志并写入数据目录 `setup-token`，0600），防止「先暴露、后配置」被抢占。
- 审计日志：`audit.jsonl`，客户端 IP 以 HMAC 假名化存储（见「审计日志」节）。
- 会话持久化：`sessions.jsonl`（0600），重启恢复；写失败时认证不受影响，设置页提示重启后需重新登录。
- 登录页与 API 响应均带安全头：严格 CSP、`nosniff`、`DENY` 防嵌框、`no-referrer`、`noindex`、`no-store`。
- Cookie `HttpOnly + SameSite=Lax`：JS 不可读、跨站请求不携带。
- 登录/初始化端点本身公开（认证的必然入口）：`/dsh-webui-auth/login`、`/dsh-webui-auth/setup`（后者受 setup token 保护）。

## 已知边界

- **运行时包装的固有窗口**：路由对象被替换（服务热重载）到下一次重扫之间（≤10s）存在未保护窗口；启用认证时的 fail-closed 已挡住「初始裸奔」，此窗口仅影响运行中的热重载场景。
- **WS 与 trustedHosts**：反代/局域网（非回环 Host）下，WS 下行需在 dsh 配置 `client-connection.trustedHosts` 中加入对外域名（见「架构」节）。
- **反代不同机**：若反代与 DSH 不在同一台机器（对端非回环），代理头不被信任，限流将按代理 IP 聚合（退化为全局桶）。
- **审计假名化的边界**：HMAC 密钥与审计日志同目录（0600），能读取密钥文件的本地攻击者可对 IP 空间暴力还原；假名化防的是「日志明文落盘」，不是防有文件权限的攻击者。
- 会话存于数据目录 `sessions.jsonl`：重启后仍生效（到期时间不变）；关闭/卸载插件不影响凭据。
- 威胁模型为「浏览器/网络客户端」：能直接读写宿主进程内存或文件的本地进程不在防护范围内。
