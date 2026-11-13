# macOS 隔离：当前状态与边界

日期：2026-11-13（第五轮）
状态：**尽力而为层已实现**；硬件级设备隔离仍未实现

## 结论

macOS 版现在有三层可落地的强化，**都不需要关闭 SIP、不需要改签名、不需要 root**：

1. **网络强制（内核级）**：账号的 Claude 跑在 macOS 的 Seatbelt 沙盒（`sandbox-exec`）里，沙盒规则**拒绝一切出站连接，只放行本机回环**（账号中继就在那里）。规则由内核执行并被每个子进程继承，绕过代理的进程会直接断网。启动前自检：沙盒内直连外部地址必须失败、本机中继必须可达，否则**拒绝启动**（fail-closed）。
2. **密码保护**：`settings.json` 里的节点密码、订阅信息等不再以 `plain:` 保存，改为登录 Keychain 中的 32 字节主密钥 + AES-256-GCM（`keychain:` 前缀）。旧文件里的 `plain:` 会在启动时迁移。Keychain 不可用时才退回文件权限，并记录日志。
3. **网页指纹（脚本级）**：Claude Desktop 是 Electron。以随机 `--remote-debugging-port` 启动后，Hydra 通过本机 DevTools 通道在页面脚本之前注入按账号派生的指纹脚本：Canvas 像素、WebGL 的 GPU 厂商/型号、文字与元素测量（字体探针）、屏幕分辨率、CPU 核数与内存。与 Windows 账号浏览器用的是同一套派生逻辑。

**明确不做的**（这也是与 Windows + Sandboxie 的真实差距）：主机名、网卡 MAC、`IOPlatformUUID`、主板/磁盘序列号等**系统级硬件标识仍是主机的**。macOS 没有 Sandboxie 那种"往进程注入并改写内核返回值"的能力：SIP/hardened runtime 挡住 DYLD 注入，kext 在 Apple Silicon 上不可用，System Extension / Endpoint Security 只能阻断/观察、不能改写，`sandbox-exec` 只能 allow/deny。要"同一时刻每个账号看到不同硬件"，只有虚拟机——而 macOS guest 受 Apple 许可数量限制，Apple Silicon 上的 Windows ARM 虚拟机也无法加载 Sandboxie 的 x64 内核驱动。详见文末「为什么不是 Sandboxie 对等」。

## 实现

### 网络：Seatbelt 配置

每个账号一份配置：`~/Library/Application Support/ClaudeHydra/macos-sandbox/<账号散列>.sb`（0600）。

```
(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:<中继端口>"))
(allow network-outbound (remote unix-socket))
(deny network-outbound (remote unix-socket (path-literal "/var/run/mDNSResponder")))
```

只放行**账号中继这一个端口**，而不是整个回环：本机代理（Clash 的 7890、Surge 等）和其他账号的中继也监听在回环上，放开 `localhost:*` 就等于给了一条走主机或别的账号出口的路。Seatbelt 的主机部分只接受 `*` 或 `localhost`（**数值写法 `127.0.0.1:…` 会让整份配置加载失败**），端口部分可以写具体数字。代价：沙盒内的 Claude Code 连不上本机其他回环服务（本地 MCP、IDE 扩展端口等）。

- 没有代理节点（`relay_port = None`）时只写 `(version 1)(allow default)`：与 Windows 一致，没有中继就没有出口可强制，账号按普通方式出网。
- 启动命令是 `/usr/bin/sandbox-exec -f <配置> <Claude.app/Contents/MacOS/Claude> <参数…>`，环境变量（`TZ`、代理变量等）随命令传入，沙盒由 Claude 及其所有子进程继承。
- **启动前自检**（`macos::verify`）：
  1. `sandbox-exec -f <配置> /usr/bin/true` 必须成功 —— 配置能被内核加载；
  2. `sandbox-exec -f <配置> /usr/bin/nc -z -w 2 127.0.0.1 <中继端口>` 必须成功 —— 中继可达；
  3. Hydra 在沙盒外临时监听一个回环端口，`sandbox-exec -f <配置> /usr/bin/nc -z -w 2 127.0.0.1 <该端口>` 必须**失败** —— 回环上的其他端口（本机代理、其他账号中继）确实被拒；
  4. `sandbox-exec -f <配置> /usr/bin/nc -z -w 2 1.1.1.1 443` 必须**失败** —— 直连确实被拒（主机本身连不上 1.1.1.1 时这一项不能证明什么，第 3 项不受影响）。
  任一不成立都不启动账号，并给出具体原因。

### 密码：登录 Keychain

- 主密钥：32 字节随机数，存为 Keychain 通用密码项（服务 `Claude-Hydra`，账号 `settings-key`），只在 Keychain 明确返回“条目不存在”（`security` 退出码 44）时创建，且创建时不带 `-U`，绝不覆盖已有主密钥；钥匙串未解锁、用户拒绝授权、读出的值损坏等情况一律视为“暂不可用”，不写 Keychain。读到的密钥进程内缓存，失败不缓存（下次调用重试）。
- 密封格式：`keychain:` + base64(版本号 1 字节 + 12 字节随机 nonce + AES-256-GCM 密文与 tag)。加密密钥就是主密钥；`settings.json` 泄露但 Keychain 未被攻破时，密码不可解。
- 旧值：启动时后台先取得主密钥（可能等待用户解锁，此时不持锁），再在**与 `settings::update` 相同的文件锁**下扫描 `settings.json`，把 `plain:` 开头的字符串重新密封（只在确实换成了更强方案时改写；文件原子替换、0600），不会与同时进行的设置写入互相覆盖。`dpapi:`（Windows 写入）在 macOS 上解不开，按"需要重新输入"处理，与 Windows 换机一致。
- Keychain 不可用（无登录会话、用户拒绝授权）时不丢密码：退回 `plain:` 并写日志。

### 网页指纹：DevTools 注入

- 仅对**非默认账号**（有自己的 `--user-data-dir`）启用：启动参数带 `--remote-debugging-port=<随机空闲端口>`，Chromium 会在该目录写入 `DevToolsActivePort`。
- 启动线程轮询该文件，经 `http://127.0.0.1:<端口>/json/list` 找到 `page` / `webview` 目标，逐个建立 WebSocket（不发送 `Origin`，避免 remote-allow-origins 拒绝），发送 `Page.enable` 与 `Page.addScriptToEvaluateOnNewDocument` 注入指纹脚本，并等到 Chromium 对该命令返回成功才算注入。
- 这类脚本归属于安装它的 DevTools 会话，会话一断 Chromium 就会移除脚本，所以**每个页面的 WebSocket 一直保持打开**（后台线程应答 ping），直到页面或 Claude 关闭。
- `addScriptToEvaluateOnNewDocument` 不作用于已经显示的文档：对 `http(s)` 网页（claude.ai、登录页）注入后会 `Page.reload` 一次；Claude 自己的外壳页（`file:` / `app:`）不重载。
- 观察线程在调试端口存活期间一直运行，之后新开的窗口同样注入；启动前会删除上次遗留的 `DevToolsActivePort`，避免读到旧端口。
- 与 Windows 版本完全相同的一段脚本（`browser.rs::FINGERPRINT_JS`）：按账号派生、同一张画布读两次一致、不同账号不同、改动至多 1 个色阶或零点几像素、函数伪装成 `[native code]`。
- 失败降级：Claude 20 秒内不开放调试端口、WebSocket 被拒、注入命令被拒或 10 秒内无回复 —— 都只写日志（`hydra-error.log` 中的 `not installed in page …`），不阻止账号运行；此时网页指纹不生效，网络强制仍然生效。

## 已验证

本仓库的开发机是 Windows，macOS 的系统调用无法在那里执行；能在此验证的都验证了：

- `cargo test --lib`：**86 个单元测试通过**，其中新增
  - `secret::`：AES-GCM 往返与篡改检测、跨平台前缀、`plain:` 迁移（只在可加密时改写、空值不动、损坏文件不碰）、迁移等待并发的设置写入、Keychain 只在“条目不存在”时建新主密钥；
  - `macos_isolation::`：Seatbelt 配置文本（有/无中继）、只放行中继端口的 Seatbelt 配置、`DevToolsActivePort` 解析、`/json/list` 目标过滤与重载判定、CDP 回复按 id 匹配、CDP 命令 JSON、WebSocket 握手头、三种长度形式的掩码帧往返、未掩码服务端帧解析；
  - `browser::`：指纹脚本同账号稳定/跨账号不同、`node --check` 语法、Node 桩上真实执行（同一画布两次一致、跨账号像素哈希不同、偏移在界内）。
- `cargo check` 无警告：`macos.rs`、`macos_isolation.rs`、`secret.rs` 的 Keychain 部分在 Windows 上也会被编译和类型检查。**`launcher.rs`、`lib.rs`、`sandbox.rs` 中 `#[cfg(target_os = "macos")]` 的分支在 Windows 上不编译**，`cargo check --target aarch64-apple-darwin` 在 Windows 上卡在 `objc2-exception-helper` 的构建脚本，因此这些分支需要在 Mac 或 macOS CI 上先编译一次。
- 前端 `tsc --noEmit` 通过。

**macOS 上需要验收的**（首次启用时请按顺序做一遍）：

1. `sandbox-exec` 是否存在：`ls -l /usr/bin/sandbox-exec`。某些未来版本可能移除；不存在时界面会提示隔离不可用，账号不会被静默地无沙盒启动。
2. 启用一个环境的“沙箱隔离”，启动该账号，然后：
   - `pgrep -fl sandbox-exec` 能看到 `sandbox-exec -f …/macos-sandbox/<hash>.sb …/Claude`；
   - 手工验证直连被拒：`sandbox-exec -f "$HOME/Library/Application Support/ClaudeHydra/macos-sandbox/<hash>.sb" /usr/bin/nc -z -w 2 1.1.1.1 443` 应失败；把同一条命令去掉 `sandbox-exec` 应能成功（有网时）；
   - 手工验证回环其他端口被拒：本机开着 Clash 等代理时，`sandbox-exec -f <同一配置> /usr/bin/nc -z -w 2 127.0.0.1 7890` 应失败；
   - 若启动时自检失败，界面会直接报错且 Claude 不会启动。
3. 网页指纹：查看 `~/Library/Application Support/ClaudeHydra/logs/hydra.log` 是否出现 `account browser fingerprint: installed in page https://claude.ai`（每个页面一行，只记协议和主机）；**只看日志不够**，还要在该账号里打开一个 Canvas 指纹测试页，确认两个账号的哈希不同、同一账号重启后相同；也可在 Claude 的 `--user-data-dir` 里看到 `DevToolsActivePort`。若 Claude 没有开放调试端口，日志会写一条提示，功能不生效但不影响使用。
4. 密码：`security find-generic-password -s Claude-Hydra -a settings-key -w` 能取到主密钥；`settings.json` 中不应再有 `plain:` 开头的值（`grep -o '"plain:[^"]*"' settings.json`）。第一次访问 Keychain 可能弹出授权框，选择“始终允许”即可。

## 能力边界（与 Windows + Sandboxie 对比）

| 能力 | Windows + Sandboxie | macOS（本轮） |
|---|---|---|
| 网络强制 | 内核驱动按进程树阻断，只放行中继；另有 DNS 守卫 | **有**：Seatbelt 内核级 allow/deny，只放行本账号中继端口；自检失败即拒启动。弱在依赖已弃用的 `sandbox-exec`；无法像 WFP 那样按连接做更多策略 |
| 域名解析 | 守卫阻断本机 DNS，域名只经中继 | **不保证**：系统解析器（mDNSResponder，盒外进程）仍可能解析域名；但解析结果无法用于直连（出站被拒），实际出网只能经中继。属于信息泄漏面，非出口泄漏 |
| 防火墙/系统级网络可见性 | 由 Sandboxie 驱动承担 | 无 Network Extension（需要 Developer ID + entitlement + 用户授权，当前构建未签名） |
| 网页指纹（Canvas/WebGL/GPU/字体/屏幕） | 账号浏览器注入，脚本级 | **有**：Claude 渲染进程经 DevTools 注入同一套脚本；脚本级、可检测；依赖 Claude 开放调试端口，失败降级 |
| 系统级硬件标识（主机名、MAC、IOPlatformUUID、序列号） | 每个沙盒不同（机器 ID、卷号、MAC、主机名、序列号等） | **无**：仍是主机值。没有等价的注入/改写机制 |
| 文件 / 注册表隔离 | 沙盒虚拟化 + 账号数据目录 | 仅每账号独立 `--user-data-dir`；没有文件系统虚拟化（Seatbelt 只能 deny，不能 copy-on-write） |
| 密码保护 | DPAPI（当前用户） | **有**：登录 Keychain 主密钥 + AES-256-GCM |
| 进程内身份（用户名/SID） | 每账号派生 | 无：macOS 账号与 SID 是主机用户（没有注入层可改） |

## 本地调试端口的风险

`--remote-debugging-port` 会让 Claude 在 `127.0.0.1` 上开一个 DevTools 端口（端口随机，账号退出后消失），Hydra 在账号运行期间一直持有各页面的会话。连上该端口即可完全控制该账号的页面，包括读取 claude.ai 的登录态。沙盒内的进程（该账号自己的 Claude Code 等）因为只能连中继端口而连不上它；但**沙盒外**同一台机器上的任何本地进程（包括其他用户的进程）在该账号运行期间都能连上——这是为了在不改签名的情况下注入网页指纹必须付出的代价。如果对此不可接受，可在环境配置里关闭沙盒隔离（同时失去网络强制与网页指纹）。

## 为什么不是 Sandboxie 对等（以及唯一能对等的路）

- **注入**：`DYLD_INSERT_LIBRARIES` 对 hardened runtime + library validation 的签名应用无效；要注入必须复制并重签 Claude，更新会坏，产品上不可接受。原则上不需要关 SIP（第三方应用可以 ad-hoc 重签），但仍是对签名应用动手脚。
- **改写内核值**：kext 在 Apple Silicon 上不可用；System Extension / Endpoint Security 只能阻断；没有 interposer。`sandbox-exec` 只 allow/deny，不虚拟化。
- **静态标识**：主机名、MAC、`IOPlatformUUID`、序列号都是全机一份，per-user 也不隔离。
- **VM**：唯一能做到“每账号不同硬件”的路，但（a）项目当前 macOS 产物未签名/未公证，Virtualization.framework 需要 Developer ID + `com.apple.security.virtualization` entitlement；（b）macOS guest 的许可数量有限（现行条款通常为两台）；（c）Apple Silicon 上的 Windows ARM 虚拟机无法加载 Sandboxie 的 x64 内核驱动，Intel Mac 才可能；（d）每个 VM 的安装、内存与登录成本很高。

因此 macOS 版能承诺的是：**出口、时区、语言、账号数据、网页指纹按账号隔离，网络出口被内核强制；硬件标识与主机一致。** 这比“只用代理环境变量”强得多，但达不到 Windows + Sandboxie 的强度，文档和界面都按这个口径说明。

## 后续可选项

1. **签名与 Network Extension**：拿到 Developer ID 并公证后，可用 Network Extension 按进程重定向/丢弃流量，替代已弃用的 `sandbox-exec`（仍需用户批准系统扩展）。
2. **VM 方案**：签名、许可与资源评估通过后，每账号（或每台 Mac 上的少量高风险账号）一台 macOS VM；或对 Claude Code（Node CLI）账号用 Linux VM，身份完全可控。
3. **Claude Code CLI**：若使用命令行账号，可用 `NODE_OPTIONS=--require` 预加载脚本覆盖 `os.hostname()`、`os.networkInterfaces()`、`os.userInfo()`，不需要注入原生代码；本轮未接入。
