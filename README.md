<div align="center">

<img src="app/src/assets/claude-hydra-icon-256.png" alt="Claude-Hydra" width="140">

# Claude-Hydra

**同时运行多个 Claude 桌面端账号，每个账号配置防泄漏策略，拥有独立的数据目录、代理节点与时区；可选虚拟沙盒隔离，并内置按账号派生的设备与网页指纹。**

基于 Tauri 2（Rust + React）构建，支持 Windows 与 macOS。

![Windows 10 | 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square&logo=windows)
![macOS](https://img.shields.io/badge/macOS-11%2B-000000?style=flat-square&logo=apple)
![Tauri 2](https://img.shields.io/badge/Tauri-2.x-24C8DB?style=flat-square&logo=tauri)
![License: MIT](https://img.shields.io/badge/License-MIT-2e7d4a?style=flat-square)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/accounts-dark.png">
  <img src="docs/images/accounts-light.png" alt="Claude-Hydra 账号页" width="760">
</picture>

</div>

## 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [环境配置](#环境配置)
- [防泄漏机制](#防泄漏机制)
- [沙盒隔离](#沙盒隔离)
- [设备与网页指纹](#设备与网页指纹)
- [避免直连的使用建议](#避免直连的使用建议)
- [时区同步](#时区同步)
- [用量统计](#用量统计)
- [会话迁移](#会话迁移)
- [平台差异](#平台差异)
- [数据存储与安全](#数据存储与安全)
- [已知限制](#已知限制)

## 功能概览

| 功能 | 说明 |
| --- | --- |
| 多账号并行 | 通过 `--user-data-dir` 为每个账号提供独立的配置与登录态，可同时打开多个 Claude 窗口 |
| 环境配置 | 把代理节点、时区、窗口语言、启动参数与环境变量保存为“环境”，多个账号共用，修改一处同步生效 |
| 代理节点 | 支持 Clash 订阅节点（内置 Mihomo 内核，无需另装）与自定义 SOCKS5 / HTTP / HTTPS 节点，附出口检测与换 IP 链接 |
| 防泄漏 | 内置本机中继，DNS、UDP/QUIC、IPv6 全部经节点或被阻止；节点失效时断网而非直连 |
| 沙盒隔离 | 可按环境开启：Windows 用 Sandboxie-Plus、macOS 用系统 Seatbelt 沙盒，账号只能经自己的中继出网，绕过代理的进程直接断网 |
| 设备与网页指纹 | Windows 沙盒内的机器 ID、主机名、MAC、账号 SID、硬件序列号等按账号派生；Canvas、WebGL、字体、屏幕、CPU 与内存等网页指纹按账号派生 |
| 出口保护 | 环境可绑定出口国家 / IP，启动前与运行中持续核对，出口不符时切断该账号网络 |
| 时区同步 | 时区可跟随代理出口、跟随系统或手动指定；确认出口后直接显示具体时区 |
| 用量统计 | 按账号查看订阅的 5 小时与每周额度 |
| 会话迁移 | 在账号之间复制本地 Claude Code 会话；普通聊天可导出后续聊 |

## 快速开始

1. 打开 **Claude-Hydra**，在左侧 **环境配置** 中点击 **新建环境**，选择代理方式并点 **连通检测** 确认出口（不需要代理可跳过）。
2. 回到 **账号** 页，点击右上角 **+ 添加账号**，填写窗口名称并选择环境，点击 **确定**。
3. 在弹出的全新 Claude 窗口中登录，即可与其他账号同时在线。
4. 点击账号卡片上的 **启动** 打开账号，运行中时可点 **关闭**；双击卡片可启动账号或切到它的窗口。右侧 **···** 菜单可编辑、重启或打开数据目录。

## 环境配置

<div align="center">
<img src="docs/images/environments.png" alt="环境配置列表" width="720">
</div>

环境保存后可在任意账号中选择使用，修改会作用于所有使用它的账号。列表中显示代理节点、已确认的出口时区与窗口语言。

<div align="center">
<img src="docs/images/environment-edit.png" alt="编辑环境配置" width="720">
</div>

| 字段 | 说明 |
| --- | --- |
| 窗口语言 | 以 `--lang` 启动 Claude，如英语（美国）、日语 |
| 代理方式 | **Clash 代理**：填写订阅地址并点 **读取订阅**，从列表中选择节点；由内置的 Mihomo 内核运行，支持 Clash 的各类协议<br>**自定义代理**：SOCKS5 / HTTP / HTTPS，可选 IPv4 / IPv6 出口 |
| 代理主机 / 端口 | 自定义代理时使用；主机栏可粘贴 `socks5://主机:端口:账号:密码`、`账号:密码@主机:端口`、`主机:端口:账号:密码`，自动拆分 |
| 账号密码 | 选填，最多 200 个字符；只保存在本机，不会出现在 Claude 的启动参数或环境变量中 |
| 出口检测 | 检测出口所用的服务：ipinfo.io / ipapi.co / ip-api.com。**连通检测** 经节点查询出口 IP、地区、时区、家宽 / 机房判断与风险记录，结果随环境保存 |
| 前置代理 | 选填，链式代理：本机 → 前置代理 → 节点 → 目标网站，出口仍是节点（适合家宽落地）。最多 3 级，由内置 Mihomo 串联，任何一跳失败即断开 |
| 刷新 URL | 服务商提供的换 IP 链接，点击右侧按钮直接请求（不经过节点） |
| 出口规则 | 把出口国家 / IP 绑定到环境；启动前与运行中核对，不符时断网，可在账号菜单 **恢复网络** 或在环境中 **重新绑定** |
| 独立 Code | 每个账号使用独立的 Claude Code 登录与配置；开启沙盒隔离时强制开启 |
| 沙箱隔离 | 见 [沙盒隔离](#沙盒隔离) |
| 时区 | 见 [时区同步](#时区同步) |
| 额外启动参数 / 环境变量 | 高级选项；代理相关参数与变量由 Hydra 管理，不能手动覆盖 |

保存后，新建的连接立即使用新节点；时区、窗口语言与启动参数在重启该账号后生效。

## 防泄漏机制

配置了节点的账号，网络路径为：

```text
Claude 窗口 / 子进程 ──► 127.0.0.1 本机中继（Hydra 后台）──► 代理节点 ──► 互联网
                                        └─ Clash 节点经内置 Mihomo 内核转换
```

Claude 只看得到本机中继地址；节点的账号密码保存在 Hydra 内部，不会出现在 Claude 的启动参数或环境变量中。

| 泄漏途径 | 处理方式 |
| --- | --- |
| DNS | 通过 SOCKS5 代理（`--proxy-server=socks5://…`）把域名原样交给节点解析；Claude 自身已关闭 DNS 预解析 |
| WebRTC | 传入 `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` 等开关。Electron 可能不采用这些开关，实际策略以 Claude 自身设置为准，Hydra 不能从外部保证 |
| UDP / QUIC | `--disable-quic`；中继拒绝 SOCKS5 UDP ASSOCIATE |
| IPv6 | Claude 只连接 127.0.0.1 中继，不直接使用本机 IPv6 |
| 子进程 | Claude Code、MCP 等通过 `HTTP(S)_PROXY`、`ALL_PROXY`、`NODE_USE_ENV_PROXY` 指向同一中继 |
| 节点失效 | 每次启动前经“中继 → 节点”检测出口，失败不启动；运行中节点断开或 Hydra 退出，该账号断网，不回退直连 |

上述开关已用无头 Chrome 实测：WebRTC 候选地址由 3 个降为 0；中继关闭时页面无法加载。

> Claude 会拒绝带 `--host-resolver-rules` 等网络覆盖开关的启动，因此 Hydra 不使用这类开关，也会在保存环境时拦截它们。

> 账号运行期间请保持 Claude-Hydra 在托盘中运行。

## 沙盒隔离

不开沙盒时，Claude 及其子进程经本机中继出网，但不读取代理设置、自行直连的程序仍可能绕过节点。在环境中开启 **沙箱隔离** 后，由操作系统强制执行网络限制：

| | Windows（Sandboxie-Plus） | macOS（Seatbelt） |
| --- | --- | --- |
| 前提 | Windows 安装程序请求管理员授权，自动安装随包附带的 [Sandboxie-Plus 1.18.8](https://github.com/sandboxie-plus/Sandboxie/releases/tag/v1.18.8)，或复用已安装的组件。安装后在环境配置中打开或关闭「沙箱隔离」并保存 | 系统自带 Seatbelt，启用沙箱无需安装驱动或管理员授权 |
| 网络 | 只允许连接本账号的本地中继，任何绕过代理的进程都会断网 | 拒绝一切出站连接，只放行本账号中继的端口；本机 Clash 等代理和其他账号的中继也连不上 |
| DNS | 注入防护模块，拒绝系统 DNS 通道、拦截发往非本机地址的连接，域名只经节点解析 | 屏蔽系统 DNS 服务，域名只经节点解析 |
| 文件与注册表 | 写入留在沙箱内（账号数据目录除外） | 不虚拟化；禁止读写其他账号的数据和 Hydra 配置 |
| 设备标识 | 按账号派生，见 [设备与网页指纹](#设备与网页指纹) | 仍为主机本身的值 |
| 启动校验 | 启动后核实 Claude 确实在沙箱中，否则立即关闭 | 启动前自检：中继可达、直连和其他本机端口被拒、读不到 Hydra 配置，任一不成立就不启动 |

- 沙盒由 Claude 启动的所有子进程继承，包括 Claude Code、git 和 MCP 服务。Windows 沙箱内还会为 git 生成专用配置，把它的代理也指向中继。
- 开启沙盒时会强制使用 **独立 Code** 目录，避免各账号报出同一个 Claude Code 设备 ID。
- Windows 商店版会先复制一份到 Hydra 数据目录再装入沙箱，首次启动较慢。
- Windows 沙箱默认静默启动。可从 **设置 → 沙箱设置 → 打开沙箱管理** 打开管理器。全新默认安装时组件位于 Hydra 目录下的 Sandboxie-Plus 子目录，不创建桌面快捷方式。自选 Hydra 安装目录时，沙箱组件使用 Sandboxie 的系统安装位置。
- macOS 沙盒内的 Claude Code 连不上本机其他回环服务（如本地 MCP、IDE 扩展端口）。这是只放行中继端口的代价。
- macOS 不允许沙箱嵌套，开启沙盒的账号必须以 `--no-sandbox` 运行 Claude，也就是关闭 Chromium 自带的渲染进程沙箱。网页一旦被攻击，影响范围会比平时大，文件规则只能降低这种影响。
- macOS 沙盒内只有 Claude 主进程能打开链接和其他应用。Claude Code 等子进程不能用 `open` 或 AppleScript 启动应用，需要浏览器登录时请手动打开它给出的链接。

实现细节与边界：[docs/macos-isolation-status.md](docs/macos-isolation-status.md)、[docs/fingerprint-device-isolation-status.md](docs/fingerprint-device-isolation-status.md)。

## 设备与网页指纹

指纹由账号 ID 确定性派生：**同一账号每次启动看到的都是同一台“设备”，不同账号互不相同**，不随重启变化，也不是每次随机生成。

**设备标识（Windows，开启沙箱隔离时生效）**

| 标识 | 说明 |
| --- | --- |
| 机器 ID / 硬件配置 ID | `MachineGuid`、`HwProfileGuid`，注册表各种读法结果一致 |
| 主机名与账号域 | `DESKTOP-` 开头，`COMPUTERNAME`、`USERDOMAIN` 等环境变量同步改写 |
| 账号名与 SID | 文本与二进制两种形式，`whoami /user` 与 .NET 都报沙箱内账号 |
| 网卡 MAC | 按网卡派生的本地管理地址 |
| 卷序列号 | 每个卷各一个，Node 的 `fs.stat` 等读法结果一致 |
| 主板 / BIOS / 内存 / 磁盘序列号、系统 UUID | 改写 SMBIOS 表与磁盘描述符 |
| WMI | 沙箱内关闭，避免由沙箱外服务报出主机硬件 |

**网页指纹**

| 项目 | 说明 |
| --- | --- |
| Canvas | 像素按账号加入微小扰动（至多 1 个色阶） |
| WebGL | GPU 厂商与型号 |
| 字体探针 | 文字与元素测量（零点几像素级） |
| 屏幕 | 分辨率 |
| 硬件 | CPU 核数与内存大小 |

- Windows：作用于 **账号浏览器**，即登录与外部链接打开的独立窗口，它与账号使用同一出口 IP 和同一时区。
- macOS：同样作用于账号浏览器，不注入 Claude 窗口。Claude 会拒绝带 `--remote-debugging-port` 的启动。

**不覆盖的部分**：沙盒是进程级隔离，不是虚拟机。CPU 型号、内存大小、显卡与驱动版本仍与主机一致；macOS 上的主机名、MAC、`IOPlatformUUID`、硬件序列号仍为主机的值；你自己的 Chrome / Edge 不经过指纹脚本。需要完全独立的硬件环境时，请使用虚拟机。

## 避免直连的使用建议

代理节点只在通过 Claude-Hydra 启动账号时生效（主界面、托盘）。直接打开 Claude 时，它会进入**默认账号**，不经过任何节点。Hydra 创建的额外账号无法被直接打开，因此按以下方式使用即可避免账号直连：

1. **默认账号保持未登录。** 如果默认账号曾经登录过，请先在 Claude 中退出登录。之后无论是直接打开 Claude，还是 Claude 自动更新后自行重启，看到的都只是一个未登录的空白窗口，不会带着你的账号用真实 IP 联网。
2. **所有需要代理的账号都在 Hydra 中创建并登录。** 默认账号不建议配置代理节点。
3. **登录时让系统网络也走同一节点。** Google 等方式的登录页在系统认证窗口或浏览器中打开，走的是系统网络而不是 Hydra 的节点。登录前请让系统代理（例如 Clash）临时切换到与该账号相同的节点，登录完成后再恢复。
4. **账号运行期间不要退出 Claude-Hydra。** 退出后已配置节点的账号会断网，不会回退直连，重新打开 Hydra 即可恢复。
5. **留意自行联网的工具。** 不读取代理环境变量、自行直连网络的 MCP 服务或命令行工具可能绕过节点，请优先选用支持 `HTTPS_PROXY` 的工具。

> macOS 上点击 Dock 中的 Claude 时，若已有 Hydra 账号在运行，系统通常会切换到该窗口而非新开默认账号；需要打开默认账号时请从 Hydra 启动。

## 时区同步

| 选项 | 行为 |
| --- | --- |
| 跟随代理 IP（默认） | 每次启动时经节点查询出口时区并应用；查询不到则不启动。确认过出口后，选项与环境列表直接显示具体时区，如 `America/Los_Angeles` |
| 跟随系统 | 不修改时区 |
| 自定义 | 使用指定的 IANA 时区，如 `Asia/Tokyo` |

时区通过 `TZ` 环境变量传给 Claude。macOS 上 Claude 窗口与子进程均生效；Windows 上 Claude 窗口可能仍显示系统时区，仅子进程确定生效。

## 用量统计

<div align="center">
<img src="docs/images/usage.png" alt="用量统计" width="720">
</div>

在 **用量** 页点击账号右侧的 **刷新**，读取 Claude 返回的 5 小时与每周额度（包含同账号在其他设备上的用量）。只在点击时联网，同一账号 60 秒内不重复请求；配置了节点的账号经节点查询。

- Windows：使用当前 Windows 用户解密本机登录凭据。
- macOS：首次读取时系统会询问是否允许访问钥匙串中的“Claude Safe Storage”，请选择“允许”。
- 用量凭据由 Claude 桌面端在使用 Claude Code 等功能时生成。只登录、从未使用过这些功能（或因身份验证等原因无法使用）的账号暂时无法读取用量，页面会给出说明。

此接口未公开，可能随 Claude 更新而变化。

## 会话迁移

<div align="center">
<img src="docs/images/sessions.png" alt="会话迁移" width="720">
</div>

**Claude Code 会话**：选择来源账号后，会话按工作目录分组列出（标题、最后活动时间、模型、轮数），可单个、整组或勾选后迁移到其他账号；也可移入回收站或还原。

1. 来源账号可以保持运行；目标账号正在运行时，Hydra 会提示需要重启，确认后自动关闭、复制并重新启动它（桌面端只在启动时读取会话列表）。
2. 目标账号必须已至少有一个 Claude Code 会话，且只登录了一个身份。
3. 只复制会话索引（`claude-code-sessions` 下的 `local_*.json`），原文件保留，同名会话跳过不覆盖。

**普通聊天续聊**：在来源账号中通过“设置 → 隐私 → 导出数据”导出，点击 **导入聊天JSON** 选择解压后的 `conversations.json`，将聊天保存到目标账号的会话列表，打开后可作为附件在新聊天中继续对话。

## 平台差异

| 功能 | Windows | macOS |
| --- | --- | --- |
| 多账号 | ✅ | ✅ |
| 环境配置、代理节点与防泄漏中继 | ✅（商店版默认账号除外） | ✅ |
| 沙盒隔离 | ✅ Sandboxie-Plus（网络、文件、注册表） | ✅ Seatbelt（网络与账号间文件访问，需关闭渲染进程沙箱） |
| 设备标识派生 | ✅ 沙箱内 | ❌ 仍为主机值 |
| 网页指纹 | ✅ 账号浏览器 | ✅ 账号浏览器 |
| 时区同步 | ⚠️ 子进程生效，窗口待实测 | ✅ |
| 用量统计 | ✅ | ✅ |
| 会话迁移 / 聊天续聊 | ✅ | ✅ |

## 数据存储与安全

| 平台 | 根目录 |
| --- | --- |
| Windows | 存在 D 盘时为 `D:\ClaudeHydra`，否则为 `%LOCALAPPDATA%\ClaudeHydra`；可用环境变量 `CLAUDE_HYDRA_ROOT` 自定义 |
| macOS | `~/Library/Application Support/ClaudeHydra` |

- `settings.json`：账号与环境配置。节点密码与订阅信息在 Windows 上以 DPAPI 加密保存；macOS 上用登录钥匙串中的密钥（AES-256-GCM）加密，旧版明文配置会在启动时自动迁移，钥匙串不可用时才退回仅本人可读的文件权限。
- `profiles/<账号ID>`：额外账号的 Claude 数据目录。
- `mihomo-run/`：Clash 节点运行时的临时目录，内核退出后自动清理。
- 默认账号继续使用 Claude 原有的数据目录。

## 已知限制

- 不开沙盒时，防泄漏只覆盖 Claude 的 Chromium 网络栈与读取代理环境变量的子进程；不读取代理变量、自行直连的子进程无法拦截，需要系统级保证时请开启 [沙盒隔离](#沙盒隔离)。在系统认证窗口或你自己的浏览器中打开的登录页不受 Hydra 控制。
- 设备与网页指纹降低了同一台电脑上账号被关联的可能，但不能保证账号之间一定不被关联；不开沙盒时，设备标识与主机相同。
- 使用代理节点时，额外启动参数中不能再包含 `--proxy-server` 等代理开关。
- Claude 会拒绝带调试或网络覆盖开关（如 `--remote-debugging-port`、`--host-resolver-rules`、`--ignore-certificate-errors`）的启动，Hydra 保存环境时会提示移除。
- macOS 版未经 Apple 签名公证；从浏览器下载后首次打开如提示“已损坏”，请运行 `xattr -cr /Applications/Claude-Hydra.app`。之后的版本通过应用内更新安装。
- 商店版（MSIX）的默认账号由系统启动，无法应用代理节点、时区与额外参数。
- 用量统计与会话迁移依赖 Claude 桌面端未公开的数据格式，可能随其更新失效。

## 许可证

本项目基于 [MIT License](LICENSE) 开源。



## 社区

- **[linux.do](https://linux.do)** - 学AI，上L站.
