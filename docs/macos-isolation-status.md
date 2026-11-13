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
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket))
(deny network-outbound (remote unix-socket (path-literal "/var/run/mDNSResponder")))
```

`localhost:*` 是 seatbelt 的合法写法（每个回环地址、每个端口）；**数值写法的 `127.0.0.1:*` 在 macOS 上无效**，会让整份配置加载失败，所以没有使用。

- 没有代理节点（`relay_port = None`）时只写 `(version 1)(allow default)`：与 Windows 一致，没有中继就没有出口可强制，账号按普通方式出网。
- 启动命令是 `/usr/bin/sandbox-exec -f <配置> <Claude.app/Contents/MacOS/Claude> <参数…>`，环境变量（`TZ`、代理变量等）随命令传入，沙盒由 Claude 及其所有子进程继承。
- **启动前自检**（`macos::verify`）：
  1. `sandbox-exec -f <配置> /usr/bin/true` 必须成功 —— 配置能被内核加载；
  2. `sandbox-exec -f <配置> /usr/bin/nc -z -w 2 1.1.1.1 443` 必须**失败** —— 直连确实被拒；
  3. `sandbox-exec -f <配置> /usr/bin/nc -z -w 2 127.0.0.1 <中继端口>` 必须成功 —— 中继可达。
  任一不成立都不启动账号，并给出具体原因。

### 密码：登录 Keychain

- 主密钥：32 字节随机数，存为 Keychain 通用密码项（服务 `Claude-Hydra`，账号 `settings-key`），首次使用时创建，进程内缓存。
- 密封格式：`keychain:` + base64(版本号 1 字节 + 12 字节随机 nonce + AES-256-GCM 密文与 tag)。加密密钥就是主密钥；`settings.json` 泄露但 Keychain 未被攻破时，密码不可解。
- 旧值：启动时后台扫描 `settings.json`，把 `plain:` 开头的字符串重新密封（只在确实换成了更强方案时改写；文件原子替换、0600）。`dpapi:`（Windows 写入）在 macOS 上解不开，按"需要重新输入"处理，与 Windows 换机一致。
- Keychain 不可用（无登录会话、用户拒绝授权）时不丢密码：退回 `plain:` 并写日志。

### 网页指纹：DevTools 注入

- 仅对**非默认账号**（有自己的 `--user-data-dir`）启用：启动参数带 `--remote-debugging-port=<随机空闲端口>`，Chromium 会在该目录写入 `DevToolsActivePort`。
- 启动线程轮询该文件，经 `http://127.0.0.1:<端口>/json/list` 找到 `page` / `webview` 目标，逐个建立 WebSocket（不发送 `Origin`，避免 remote-allow-origins 拒绝），发送 `Page.enable` 与 `Page.addScriptToEvaluateOnNewDocument` 注入指纹脚本；同一目标后续导航自动带上，新窗口在 120 秒观察窗内继续注入。
- 与 Windows 版本完全相同的一段脚本（`browser.rs::FINGERPRINT_JS`）：按账号派生、同一张画布读两次一致、不同账号不同、改动至多 1 个色阶或零点几像素、函数伪装成 `[native code]`。
- 失败降级：Claude 不开放调试端口、WebSocket 被拒、或 120 秒内没有页面 —— 都只写日志，不阻止账号运行；此时网页指纹不生效，网络强制仍然生效。

## 已验证

本仓库的开发机是 Windows，macOS 的系统调用无法在那里执行；能在此验证的都验证了：

- `cargo test --lib`：**83 个单元测试通过**，其中新增
  - `secret::`：AES-GCM 往返与篡改检测、跨平台前缀、`plain:` 迁移（只在可加密时改写、空值不动、损坏文件不碰）；
  - `macos_isolation::`：Seatbelt 配置文本（有/无中继）、`DevToolsActivePort` 解析、`/json/list` 目标过滤、CDP 命令 JSON、WebSocket 握手头、三种长度形式的掩码帧往返、未掩码服务端帧解析；
  - `browser::`：指纹脚本同账号稳定/跨账号不同、`node --check` 语法、Node 桩上真实执行（同一画布两次一致、跨账号像素哈希不同、偏移在界内）。
- `cargo check` 无警告：`macos.rs` 在 Windows 上也会被编译，因此其中的 Rust 逻辑（CSV 之外的全部控制流）已被类型检查覆盖。
- 前端 `tsc --noEmit` 通过。

**macOS 上需要验收的**（首次启用时请按顺序做一遍）：

1. `sandbox-exec` 是否存在：`ls -l /usr/bin/sandbox-exec`。某些未来版本可能移除；不存在时界面会提示隔离不可用，账号不会被静默地无沙盒启动。
2. 启用一个环境的“沙箱隔离”，启动该账号，然后：
   - `pgrep -fl sandbox-exec` 能看到 `sandbox-exec -f …/macos-sandbox/<hash>.sb …/Claude`；
   - 手工验证直连被拒：`sandbox-exec -f "$HOME/Library/Application Support/ClaudeHydra/macos-sandbox/<hash>.sb" /usr/bin/nc -z -w 2 1.1.1.1 443` 应失败；把同一条命令去掉 `sandbox-exec` 应能成功（有网时）；
   - 若启动时自检失败，界面会直接报错且 Claude 不会启动。
3. 网页指纹：查看 `~/Library/Application Support/ClaudeHydra/logs/hydra.log` 是否出现 `account browser fingerprint: installed in N page(s)`；也可在 Claude 的 `--user-data-dir` 里看到 `DevToolsActivePort`。若 Claude 没有开放调试端口，日志会写一条提示，功能不生效但不影响使用。
4. 密码：`security find-generic-password -s Claude-Hydra -a settings-key -w` 能取到主密钥；`settings.json` 中不应再有 `plain:` 开头的值（`grep -o '"plain:[^"]*"' settings.json`）。第一次访问 Keychain 可能弹出授权框，选择“始终允许”即可。

## 能力边界（与 Windows + Sandboxie 对比）

| 能力 | Windows + Sandboxie | macOS（本轮） |
|---|---|---|
| 网络强制 | 内核驱动按进程树阻断，只放行中继；另有 DNS 守卫 | **有**：Seatbelt 内核级 allow/deny，只放行回环；自检失败即拒启动。弱在依赖已弃用的 `sandbox-exec`；无法像 WFP 那样按连接做更多策略 |
| 域名解析 | 守卫阻断本机 DNS，域名只经中继 | **不保证**：系统解析器（mDNSResponder，盒外进程）仍可能解析域名；但解析结果无法用于直连（出站被拒），实际出网只能经中继。属于信息泄漏面，非出口泄漏 |
| 防火墙/系统级网络可见性 | 由 Sandboxie 驱动承担 | 无 Network Extension（需要 Developer ID + entitlement + 用户授权，当前构建未签名） |
| 网页指纹（Canvas/WebGL/GPU/字体/屏幕） | 账号浏览器注入，脚本级 | **有**：Claude 渲染进程经 DevTools 注入同一套脚本；脚本级、可检测；依赖 Claude 开放调试端口，失败降级 |
| 系统级硬件标识（主机名、MAC、IOPlatformUUID、序列号） | 每个沙盒不同（机器 ID、卷号、MAC、主机名、序列号等） | **无**：仍是主机值。没有等价的注入/改写机制 |
| 文件 / 注册表隔离 | 沙盒虚拟化 + 账号数据目录 | 仅每账号独立 `--user-data-dir`；没有文件系统虚拟化（Seatbelt 只能 deny，不能 copy-on-write） |
| 密码保护 | DPAPI（当前用户） | **有**：登录 Keychain 主密钥 + AES-256-GCM |
| 进程内身份（用户名/SID） | 每账号派生 | 无：macOS 账号与 SID 是主机用户（没有注入层可改） |

## 本地调试端口的风险

`--remote-debugging-port` 会让 Claude 在 `127.0.0.1` 上开一个 DevTools 端口，Hydra 用完即弃（账号退出后端口消失；端口随机）。同一台机器的其他本地进程在该账号运行期间可以连上它——这是为了在不改签名的情况下注入网页指纹必须付出的代价。账号运行在 Seatbelt 沙盒里，沙盒本身不阻止外部连入该端口；如果对此不可接受，可在环境配置里关闭沙盒隔离（同时失去网络强制与网页指纹）。

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
