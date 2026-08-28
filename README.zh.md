# dsh-security —— DeepSeek Harness（dsh）的可插拔安全套件

一套遵循**一切皆插件**理念的 dsh 安全套件。每项能力都是独立、可替换、可单独安装/升级/禁用的 Cordis 插件。一个小巧的 **核心** 插件提供共享基础设施，其余模块各自注册到核心，并统一呈现在“设置”的 **控制面板** 上。

```
┌─────────────────────────────────────────────────────────────────────────┐
│  设置 → 安全中心（控制面板）                                              │
│  • 列出所有已安装的安全模块                                              │
│  • 管理管理员密码                                                        │
│  • 管理可信 IP 列表                                                      │
└───────────────▲──────────────────────────────▲──────────────────────────┘
                │ 注册（模块清单）              │ 管理员密码 / 可信 IP
┌───────────────┴────────┐   ┌─────────────────┴───────────────────────────┐
│ @dsh-security/core     │   │ 共享设置命名空间 `dsh-security`             │
│  ctx.security 服务：    │   │ (settings.yaml)                            │
│  • 模块注册表          │   └──────────────────────────────────────────────┘
│  • 管理员密码保险库     │
│  • IP 常用度跟踪/判定   │
│  • 告警分发 ────────────┼──────▶ 任意带 `handleAlert` 的模块
└────────────────────────┘
        ▲          ▲          ▲          ▲          ▲
  攻击提醒   关键文件保护  命令执行防护  陌生IP保护   API保护
  (SMTP 邮件) (MD5 检测)  (危险拦截)   (陌生IP)    (/api 蜜罐)
```

## 模块

| 包 | 类别 | 功能 |
|---|---|---|
| `@dsh-security/core` | 核心 | 共享 `ctx.security` 服务：模块注册表、scrypt 加盐哈希的管理员密码保险库、IP 常用度跟踪/判定、告警分发。持久化到 `dsh-security` 设置命名空间。 |
| `@dsh-security/control-panel` | 界面 | 在“设置”中注册名为**安全中心**的页面，列出已安装模块、设置/修改管理员密码、维护可信 IP 列表。双面包（宿主桩 + 浏览器端）。 |
| `@dsh-security/attack-alert` | 告警 | 当任意模块调用 `ctx.security.alert()` 时，通过零依赖的 `node:net`/`node:tls` SMTP 客户端（AUTH LOGIN + 可选 STARTTLS）向配置的邮箱发送邮件。注册 `handleAlert`。 |
| `@dsh-security/file-protect` | 文件 | 定时重新计算 dsh 关键文件（默认：`$DSH_HOME/cordis.patch.yml`、web profile 补丁/配置、`settings.yaml`、`.credentials.yaml`）的 MD5，文件被修改时发邮件告警。 |
| `@dsh-security/command-protect` | 命令 | 在 `tools/pre-execute` 瀑布中为每条 `bash`/`pwsh` 命令评分危险度。危险命令被拒绝，直到管理员密码通过验证（`security_verify_password` 工具向用户询问密码）；验证通过后在限时窗口内解锁。同时包装 `ctx.shell` 作为纵深防御。 |
| `@dsh-security/ip-protect` | IP | 通过观察 webserver 上的 `/api` 流量学习常用 IP。当陌生 IP 发起对话时发邮件提醒管理员（以便其在控制面板中添加该 IP）。 |
| `@dsh-security/api-protect` | API | 注册精确的 `/api/<method>` 路由，对**未登录或陌生 IP** 的调用返回随机无意义的数据，而非真实后端响应；同时将受信任的回环/可信流量转发给真实网关。 |

### 跨模块告警（需求 9）

任意模块触发保护时都会调用 `ctx.security.alert(payload)`。若安装了 **attack-alert** 模块则发送邮件；否则核心仅记录一条警告。没有任何模块硬依赖 attack-alert——可将其替换为任意其它 `handleAlert` 提供方（例如 Webhook）。

## 各保护的实现说明

### 管理员密码（核心）
使用 **scrypt + 随机盐**（`salt:derived`）哈希。仅存储哈希，位于 `dsh-security` 设置命名空间的 `role("secret")` 字段中（网络传输时脱敏）。校验使用 `timingSafeEqual`。控制面板写入明文的 `adminPasswordPending` 字段，由核心在服务端哈希后清除，明文不会持久化。

### 命令执行防护
- 危险评分：由若干「正则 → 严重度(0–100)」规则组成；当某条命令的最高匹配规则评分 ≥ `dangerThreshold`（默认 50）时判定为危险。
- 在 **`tools/pre-execute`** 瀑布（`prepend: true`）强制拦截——这是所有工具调用的唯一前置检查点。被拒绝的命令不会启动任何进程。
- 模型被告知调用 `security_verify_password`，该工具向人类询问管理员密码，验证通过后在 `unlockTtlMs`（默认 30 分钟）内解锁危险命令执行。
- 纵深防御：同时包装 `ctx.shell.run/start`，使直接调用 shell 的调用方（如 cordis SDK）也无法绕过。

### 关键文件保护
- 每次启动及每 `intervalSeconds`，计算每个文件的 MD5 并与已存基线比对。首次观察建立基线；此后任何变化都会触发告警，且**不会**自动更新基线（持续告警，直到你手动将 `rescanBaseline` 置为 `true` 重新建立基线）。

### 陌生 IP 保护
- 在 webserver 上挂 `request`/`upgrade` 观察器，为每次 `/api` 访问记录客户端 IP 到核心 IP 跟踪器，逐步建立“常用 IP”模型。
- 陌生 IP（不可信、不常用、非回环）发起对话（`session.prompt` 等）时触发 `ctx.security.alert(...)`——邮件告知管理员在控制面板添加该 IP。
- “对陌生人不回复”的强制由 `api-protect` 实现，二者共享 `ctx.security.ip` 判定。

### API 保护
- 对每个 `/api/<method>` 注册一条精确路由，先于真实网关执行。陌生/未登录调用方收到伪造的
  `{ type: 'server-response', rpcId, result: { ok: true, value: <随机> } }` 信封；受信任的回环流量转发给 `toFetchHandler(ctx.apiProxy)`。

## 安装

### 1. 构建
浏览器端（control-panel）与其它 dsh 客户端插件一样，使用 `tsdown` 打包。宿主端为纯 ESM，无需构建：

```sh
pnpm install
pnpm --filter @dsh-security/control-panel run bundle   # 生成 lib/client.js
```

### 2. 安装到 web profile
将各包作为 profile 的依赖并安装到 profile 的 `node_modules`（profile 从那里解析树外插件）：

```sh
cd $DSH_HOME/profiles/web
pnpm add @dsh-security/core @dsh-security/control-panel @dsh-security/attack-alert \
         @dsh-security/file-protect @dsh-security/command-protect \
         @dsh-security/ip-protect @dsh-security/api-protect
```

### 3. 启用
将 [`cordis.patch.yml`](./cordis.patch.yml) 中的条目追加到 `$DSH_HOME/profiles/web/cordis.patch.yml`（profile 补丁热重载）。去掉不需要模块的行。请保留 `security-core`（其余模块依赖它）。

### 4. 配置
在“设置 → 安全中心”中修改模块设置，或直接编辑设置文件。关键项：
- **attack-alert**：设置 `smtpHost`、`smtpPort`、`smtpUser`/`smtpPass`（secret）、`from`、`to`。
- **command-protect**：调整 `dangerThreshold`，可添加自定义 `rules`（`{ name, pattern, score }`）。
- **file-protect**：在 `files` 中添加关键文件；正常升级后将 `rescanBaseline: true` 重新建立基线。
- **api-protect**：0.0.0.0 部署时，将局域网主机加入 `trustedHosts`。

## 已知限制 / 诚实说明

- **dsh 没有登录机制** —— web 载体没有认证层。因此 `api-protect` 中的“已登录”被近似为“回环或可信来源 + 非陌生 IP”。真正的登录/令牌层需要单独模块。
- **客户端界面构建**：control-panel 的浏览器端必须由 dsh 客户端构建管线（`tsdown`）生成；本仓库在 `packages/control-panel/src/client/` 提供 ES 源码。
- **命令改写**在 `tools/pre-execute` 处刻意不可用（参数被冻结）；仅支持放行/拒绝，不支持改写。直接的 `ctx.terminals` 写入不被拦截（只有 `bash`/`pwsh` 工具经过瀑布）。
- **会话解锁**是进程内、限时的标志；进程重启后重置。
- **SMTP 客户端**为最小实现（AUTH LOGIN、单个收件人）。对特殊服务器可能需要扩展。

## 开发

```sh
pnpm install
for f in packages/*/lib/index.js; do node --check "$f"; done   # 语法检查
```
