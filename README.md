# dsh-webui-auth

[English](README.en.md) | 中文

DSH WebUI 身份认证插件（持久化插件）。在「设置 → 身份认证」或首次访问登录页创建账号密码后，**未认证的浏览器无法加载 WebUI 的任何资源、调用任何接口或建立任何实时连接**——认证在 HTTP/传输层强制执行，不可通过浏览器开发者工具绕过。

## 架构

认证由四层组成：

| 层 | 机制 | 未认证行为 |
|---|---|---|
| WebUI 资源（index.html、/assets/*、SPA 路由） | 插件注册 `prefix ''` 兜底路由，校验会话后转交 frontend-static | 302 → 登录页 |
| 插件 bundle（/plugins/*） | `dsh-client-modules` 补丁：serveBundle 前校验 `webServer.webuiAuthGate` | 302 → 登录页 |
| /api RPC 接口 | `dsh-client-connection` 补丁：路由前校验同一闸门 | 401 |
| WebSocket（/api/events.mux、/api/events.host） | 同包补丁：升级握手前校验同一闸门 | 403 拒绝升级 |

会话为**服务端内存会话**，由 `HttpOnly; SameSite=Lax` Cookie（`dsh_wua_session`）携带，JS 无法读取；修改密码会**吊销所有其他会话**。

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

3. **打核心包补丁**（升级 DSH 后**无需手动重打**）：在
   `node_modules/@deepseek-ai/dsh-client-connection/lib/index.js` 与
   `node_modules/@deepseek-ai/dsh-client-modules/lib/index.js`
   中搜索 `[dsh-webui-auth patch]` 注释，确认三处会话闸门代码存在（本仓库内已打好）。插件每次启动会自动检测这些标记：缺失且锚点匹配时自动重新插入（升级 DSH 后重启即自动恢复）；若核心包结构变化导致无法自动打，会在宿主日志**和 WebUI 设置页**同时明确报错，不会静默失效
4. 重启 DSH

## 卸载

### 方式一：`dsh plugin` 命令（对应方式一安装）

1. `npx @deepseek-ai/dsh plugin --profile web remove dsh-webui-auth`（同时移除依赖与组合包层）
2. **（可选）恢复核心包源码**：删除 `dsh-client-connection/lib/index.js`（2 处）与 `dsh-client-modules/lib/index.js`（1 处）中以 `// [dsh-webui-auth patch]` 开头的代码块。**不删也没有副作用**——插件消失后闸门自动失效（补丁代码在无插件时为空操作），升级 DSH 会自然覆盖清除
3. 重启 DSH

### 方式二：手动（对应方式二安装）

1. **（可选）恢复核心包源码**（同上）
2. 删除插件目录 `profiles/web/node_modules/dsh-webui-auth/`
3. 从 `profiles/web/cordis.patch.yml` 移除挂载行：

```yaml
    - id: dsh-webui-auth
      name: 'dsh-webui-auth'
```

   此步必须做，否则重启时加载器找不到插件包会报错
4. 重启 DSH

两种方式重启后认证门禁完全关闭，浏览器无需手动清理（会话存于进程内存随进程消失，Cookie 自动失效）；如曾用旧版插件，可清除浏览器 localStorage 中的 `dsh-webui-auth.session` 残留（无害）。

## 使用

- **首次启用**：未配置凭据时认证自动关闭（所有请求放行）。打开 WebUI → 设置 → 身份认证，创建账号密码（≥8 位，含大小写字母、数字、特殊符号）并保存；或直接访问 `/dsh-webui-auth/login`，页面会显示「创建管理员账号」表单。创建后认证立即生效，当前浏览器自动获得会话。
- **之后**：未登录访问任意路径 → 跳转登录页；登录后按「会话有效期」免登录（浏览器会话 / 1 小时 / 12 小时（默认）/ 1 天 / 3 天），服务端按到期时间强制失效。「浏览器会话」模式：活跃使用期间自动续期（30 分钟窗口），关闭浏览器即失效。
- **修改 / 禁用 / 退出**：设置 → 身份认证（均需当前密码）；修改密码会吊销其他所有已登录会话。
- **忘记密码**：删除插件目录的 `dsh-webui-auth.json` 即可——后台每分钟自动检测，最多 1 分钟内认证自动关闭（无需重启），之后重新创建账号即可。

## 外观

登录页与「设置 → 身份认证」设置页都跟随 DSH **自带的外观设置**（设置 → 通用 → 外观：浅色 / 深色 / 跟随系统），不提供独立的外观开关。设置页运行在 WebUI 内，直接消费 DSH 的主题 token，天然随明暗切换；登录页是独立页面，由服务端读取当前外观偏好（settings `ui-theme.preference`）注入页面，并复刻 DSH 的 boot 逻辑：`跟随系统` 时按 `prefers-color-scheme` 解析、系统明暗切换时实时变化。登录页响应带 `cache-control: no-store`，外观变更后刷新即可生效。

## 升级 DSH 后的操作流程

1. 升级并重启 DSH → 插件检测到核心补丁缺失，自动重新插入（宿主日志记录 `re-applied core patch`）
2. 此时**设置页会显示黄色警告**「已自动恢复，请重启 DSH 使认证完全生效」——因为补丁写入的是磁盘，当前进程的核心模块仍是未打补丁的版本（`/api` 与 WebSocket 暂未受保护）
3. **再重启一次 DSH** → 补丁随核心模块加载，警告消失，四层认证完全生效
4. 若自动重打失败（核心包结构变化），设置页会显示**红色警告**并附具体原因，宿主日志同步输出 `PATCH ANCHOR NOT FOUND` 等错误

## 数据与安全

- 凭据以「随机盐 + SHA-256 哈希」保存在插件目录 `dsh-webui-auth.json`，明文不落盘。
- 登录失败限流：1 分钟最多 5 次。
- Cookie `HttpOnly + SameSite=Lax`：JS 不可读、跨站请求不携带。
- 登录/创建端点本身公开（认证的必然入口）；`/dsh-vision-helper/config` 等已注册 exact 端点不受门禁（仅配置类数据，不构成 WebUI 使用）。

## 已知边界

- **核心包补丁自动维护**：插件启动时检测 `[dsh-webui-auth patch]` 标记并自动重打（锚点匹配时），升级 DSH 后重启即恢复。自动重打对**当前进程不生效**（核心模块已加载），需再重启一次；重打失败会在宿主日志与 WebUI 设置页（黄色/红色警告横幅）同时提示，不会静默失效。
- 会话存于进程内存：重启 DSH 后所有会话失效（需重新登录）；凭据文件持久化不受影响。
- 威胁模型为「浏览器/网络客户端」：能直接读写宿主进程内存或文件的本地进程不在防护范围内。
