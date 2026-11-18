# macOS 隔离：当前状态与边界

日期：2026-11-17
状态：**网络强制与账号间文件限制已实现**；硬件级设备隔离未实现

## 结论

- 开启沙箱隔离后，Claude 跑在按账号生成的 Seatbelt 配置里，所有子进程都会继承。
- 绑定节点时，只能连接本账号的中继端口。直连、其他本机端口、UDP 和系统 DNS 都被内核拒绝。
- 账号不能读写其他账号的数据目录、默认 Claude 数据目录和 Hydra 配置。
- **代价：** macOS 不允许沙箱嵌套，Claude 必须带 `--no-sandbox`，渲染进程失去 Chromium 沙箱。
- 系统级硬件标识（主机名、MAC、`IOPlatformUUID`、序列号）仍是主机值。

## Seatbelt 配置

每个账号一份：`~/Library/Application Support/ClaudeHydra/macos-sandbox/<账号散列>.sb`（0600）。

```
(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote unix-socket (path-regex #"^/")))
(deny network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
(deny mach-lookup (global-name "com.apple.dnssd.service"))
(allow network-outbound (remote ip "localhost:<中继端口>"))
(deny file-read-data file-write* (subpath "<Hydra 数据目录>"))
(deny file-read-data file-write* (subpath "<其他账号目录>"))
(allow file-read-data file-write* (subpath "<本账号目录>"))
(allow file-read-data file-write* (subpath "<本账号 Claude Code 目录>"))
(deny file-write* (subpath "<~/Library/LaunchAgents 与 shell 启动文件>"))
(deny appleevent-send)
(deny lsopen (require-not (process-path "<Claude 主程序>")))
```

没有节点时不写网络规则，文件规则仍然生效。放行规则必须写 `file-read-data`，写 `file-read*` 盖不过前面的拒绝。

启动前自检（任一不成立就不启动）：配置能加载、本账号目录可读、Hydra 配置不可读、中继可达、其他本机端口不可达、直连 `1.1.1.1:443` 不可达。

## 实机验证

2026-11-17，Claude Desktop 4.23118.0，使用临时账号目录和只记录目标、不转发的本地假中继：

| 项目 | 结果 |
| --- | --- |
| 只加 Seatbelt | 约 5 秒后崩溃，`sandbox initialization failed` |
| Seatbelt 加 `--no-sandbox` | 持续运行，GPU、网络和渲染进程正常 |
| 带 `--remote-debugging-port` | 立即退出，`refusing to start` |
| Claude 窗口流量 | 只到中继，无其他网络连接 |
| 沙盒内直连 IP、直连域名、其他本机端口、UDP、系统 DNS | 全部失败 |
| 读写本账号目录 | 成功 |
| 读写其他账号目录、读取 Hydra 配置和默认 Claude 目录 | 全部失败 |
| 未加封堵时用 `open`、`osascript` 启动程序 | 新程序在沙盒外运行，可以绕过网络限制 |
| 未加封堵时写入 `~/Library/LaunchAgents` | 成功 |
| 沙盒内用 `launchctl bootstrap` 或 `submit` 建任务 | 失败，未形成逃逸 |
| 加封堵后 `open`、`osascript`、`NSWorkspace`、写入启动项 | 全部失败 |
| 自签程序冒用 Claude 的签名标识 | 失败，放行规则按可执行文件路径匹配 |

**未验证：** 真实账号的登录和对话、Claude 主进程实际打开登录链接、Claude Code 在沙盒内的完整使用、主窗口的 WebRTC 候选地址。

## 边界

- Claude Desktop 的钥匙串项“Claude Safe Storage”由所有账号共用，文件规则才是挡住跨账号读取的那一层。
- 主目录和项目目录没有限制，Claude Code 的正常工作需要它们。页面被攻破时这些文件仍可能被读取。
- 沙盒能防止程序绕过代理，但不是对抗恶意代码的完整边界。配置基于“默认允许”，已封堵的是实测到的逃逸途径，不能证明没有其他途径。需要防恶意代码时请用独立系统用户或虚拟机。
- 启动项封堵只覆盖 `~/Library/LaunchAgents` 和常见 shell 启动文件。
- 子进程不能用 `open` 或 AppleScript 启动应用，依赖这些能力的工具和浏览器登录流程会受影响。
- Claude 不接受调试端口，所以 Claude 窗口没有网页指纹，只有账号浏览器有。
- Electron 可能不采用命令行的 WebRTC 开关。Claude 安装包在部分页面视图里自己设置了 `disable_non_proxied_udp`。Seatbelt 也拦不住读取网卡地址，所以不承诺隐藏物理网卡 IP。
- `sandbox-exec` 已被 Apple 标记为弃用。不存在时界面提示不可用，账号不会无沙盒启动。

## 密码：登录 Keychain

- 主密钥：32 字节随机数，存为 Keychain 通用密码项（服务 `Claude-Hydra`，账号 `settings-key`），只在 Keychain 明确返回“条目不存在”（`security` 退出码 44）时创建，且创建时不带 `-U`，绝不覆盖已有主密钥；钥匙串未解锁、用户拒绝授权、读出的值损坏等情况一律视为“暂不可用”，不写 Keychain。读到的密钥进程内缓存，失败不缓存（下次调用重试）。
- 密封格式：`keychain:` + base64(版本号 1 字节 + 12 字节随机 nonce + AES-256-GCM 密文与 tag)。加密密钥就是主密钥；`settings.json` 泄露但 Keychain 未被攻破时，密码不可解。
- 旧值：启动时后台先取得主密钥（可能等待用户解锁，此时不持锁），再在**与 `settings::update` 相同的文件锁**下扫描 `settings.json`，把 `plain:` 开头的字符串重新密封（只在确实换成了更强方案时改写；文件原子替换、0600），不会与同时进行的设置写入互相覆盖。`dpapi:`（Windows 写入）在 macOS 上解不开，按"需要重新输入"处理，与 Windows 换机一致。
- Keychain 不可用（无登录会话、用户拒绝授权）时不丢密码：退回 `plain:` 并写日志。

## 为什么不是 Sandboxie 对等（以及唯一能对等的路）

- **注入**：`DYLD_INSERT_LIBRARIES` 对 hardened runtime + library validation 的签名应用无效；要注入必须复制并重签 Claude，更新会坏，产品上不可接受。原则上不需要关 SIP（第三方应用可以 ad-hoc 重签），但仍是对签名应用动手脚。
- **改写内核值**：kext 在 Apple Silicon 上不可用；System Extension / Endpoint Security 只能阻断；没有 interposer。`sandbox-exec` 只 allow/deny，不虚拟化。
- **静态标识**：主机名、MAC、`IOPlatformUUID`、序列号都是全机一份，per-user 也不隔离。
- **VM**：唯一能做到“每账号不同硬件”的路，但（a）项目当前 macOS 产物未签名/未公证，Virtualization.framework 需要 Developer ID + `com.apple.security.virtualization` entitlement；（b）macOS guest 的许可数量有限（现行条款通常为两台）；（c）Apple Silicon 上的 Windows ARM 虚拟机无法加载 Sandboxie 的 x64 内核驱动，Intel Mac 才可能；（d）每个 VM 的安装、内存与登录成本很高。

因此 macOS 版能承诺的是：**出口、时区、语言、账号数据按账号隔离，网络出口被内核强制，账号浏览器的网页指纹按账号派生；硬件标识与主机一致。**

## 后续可选项

1. **签名与 Network Extension**：拿到 Developer ID 并公证后，可评估用 Network Extension 按进程强制流量，从而恢复 Chromium 沙箱并替代 `sandbox-exec`（需要用户批准系统扩展）。
2. **VM 方案**：签名、许可与资源评估通过后，为高风险账号使用虚拟机。
3. **Claude Code CLI**：可单独评估用 Seatbelt 限制其网络，并用 `NODE_OPTIONS=--require` 覆盖 `os.hostname()` 等返回值。
