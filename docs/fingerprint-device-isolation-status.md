# 指纹 / 设备隔离：当前状态

日期：2026-11-13（第四轮更新）
状态：**部分实现**（理解 A 已做，理解 B 未做）

## 结论

"指纹 / 设备隔离"按理解 A 实现了：开启 Sandboxie 隔离的账号，在沙箱里看到的机器 ID、硬件配置 ID、卷序列号、MAC 地址、主机名、账号名与账号 SID，以及主板 / BIOS / 内存 / 磁盘序列号都换成了这个账号自己的值，与主机和其他账号都不同。

第三轮补上了前两轮列为"不打算做"的账号与固件标识，第四轮补上了 SID 的二进制形式与账号浏览器的网页指纹：

- 账号：`GetUserNameW/A`、`GetUserNameExW/A`、`LookupAccountSid/Name`（含 .NET 使用的 sechost `*Local` 形式）和 `ConvertSidToStringSid` 都按盒内身份应答；`USERNAME` 环境变量同样改写。
- 账号 SID 的二进制形式：`GetTokenInformation(TokenUser/TokenOwner/TokenPrimaryGroup/TokenGroups)` 返回派生 SID，`LsaLookupSids`、`LsaLookupSids2`、`LsaLookupNames2` 也按派生身份双向应答。`whoami /user` 和 .NET 的 `WindowsIdentity.Name` / `.User.Value` 因此都报盒内账号。
- 固件与磁盘：`GetSystemFirmwareTable('RSMB')` 返回的 SMBIOS 表在进程内改写（系统 / 主板 / 内存条序列号、系统 UUID，以及同值的机箱序列号），`IOCTL_STORAGE_QUERY_PROPERTY` 返回的磁盘序列号同样改写。
- WMI：盒内**关闭** `System32\wbem` 与 `SysWOW64\wbem`。WMI 由盒外的 `WmiPrvSE.exe` 应答，进程内改不了；关掉之后盒内任何 WMI 查询都失败，而不是返回主机的硬件序列号。**这是有意的取舍：盒内"没有硬件"好过"报的是主机的硬件"。**
- 账号浏览器的网页指纹：Canvas 像素、WebGL 的 GPU 厂商 / 型号、文本与元素测量（字体探针）、屏幕尺寸、CPU 核数与内存，都按账号派生。同一账号每次看到的浏览器相同，不同账号不同；改动至多是 1 个色阶或零点几像素。

理解 B（虚拟机级隔离）没有做，也不打算用 Sandboxie 冒充。Sandboxie 是进程沙箱，不是虚拟机：它不虚拟化内核，因此 CPU 型号、内存大小、显卡与驱动版本仍与主机一致，账号浏览器以外的浏览器（用户自己的 Chrome / Edge）、Claude Code 命令行本身也不经过网页指纹脚本，见「没有覆盖到的部分」。

macOS 没有 Sandboxie 的对等物：那边做到的是 Seatbelt 网络强制与账号间文件限制、Keychain 密码，以及账号浏览器的网页指纹；主机名、MAC、`IOPlatformUUID`、序列号等系统级硬件标识仍是主机值。详见 [macos-isolation-status.md](macos-isolation-status.md)。

## 这项任务指什么

需求原话是"加入指纹 / 设备隔离"，对标 [Claude-Cage](https://github.com/Lee-xeo/Claude-Cage)。它可以有两种理解：

| 理解 | 内容 | 状态 |
|---|---|---|
| A. 生成设备标识 | 给每个虚拟沙箱生成机器 ID、设备 ID、硬件标识、MAC、主机名、账号标识等，减少平台风控在同一台设备上关联多个账号 | 已实现，见下文 |
| B. 加强环境隔离 | 让账号运行在与主机隔离的环境里（虚拟机一类），自然拥有独立的系统环境 | 未做；Sandboxie 不能替代虚拟机 |

## Claude-Cage 实际做了什么

依据它的 README（没有查看它的 `docs/` 目录）：

- 它的"指纹设置"只包含**时区和语言**，并支持随代理 IP 自动同步。
- 它的设备隔离靠**虚拟机**：Claude 跑在虚拟机里，Cage 接管虚拟机内的全部网络流量。
- README 没有伪造机器 ID、设备 ID、硬件标识、MAC 或主机名。

也就是说，Cage 做的是理解 B，Hydra 现在做的是 A。

## Hydra 目前已有的相关能力

| 项目 | Claude-Cage | Claude-Hydra |
|---|---|---|
| 时区随代理 IP | 有 | 有（环境配置里"跟随代理 IP"） |
| 窗口语言 | 有 | 有（环境配置里"窗口语言"） |
| 网络全部走代理 | 虚拟机级接管 | 本地中继；开启 Sandboxie 时绕过代理的进程会断网，不开沙箱时忽略代理设置的程序仍可能直连 |
| 与主机的数据隔离 | 整个虚拟机 | 账号数据目录、可选 Sandboxie 沙箱、"独立 Code"目录（开沙箱时强制） |
| 独立的系统标识 | 虚拟机自带 | 开启 Sandboxie 时有，未开沙箱时与主机相同 |

## 实现方式

每个账号的标识由账号 ID 确定性地派生：`Sha256("hydra identity" || 标签 || 账号散列)`。同一个账号每次启动看到的都是同一台"设备"，不同账号之间互不相同，也不随重启漂移。

| 标识 | 取值形态 | 改写位置 |
|---|---|---|
| 机器 ID（MachineGuid） | 裸小写 GUID | `NtQueryValueKey` / `NtEnumerateValueKey`，键尾 `\Microsoft\Cryptography` |
| 硬件配置 ID（HwProfileGuid） | 带花括号大写 GUID | 同上，键尾 `\Hardware Profiles\0001` |
| 主机名 | `DESKTOP-` 加 7 位大写字母数字 | `GetComputerName[Ex]W/A`；注册表 `Tcpip\Parameters\Hostname`（同上两个 NT 调用）；账号域名 `LookupAccountSidW/A`、`LookupAccountNameW/A`、`GetUserNameExW/A(NameSamCompatible)`；环境变量 `COMPUTERNAME`、`USERDOMAIN`、`USERDOMAIN_ROAMINGPROFILE`、`LOGONSERVER` |
| 卷序列号 | 8 位十六进制，每个卷各一个 | `NtQueryVolumeInformationFile(FileFsVolumeInformation)`；`NtQueryInformationFile` 与 `NtQueryInformationByName` 的 `FileIdInformation`(59) 和 `FileStatBasicInformation`(77) |
| MAC 地址 | 本地管理、单播；前 3 字节按账号固定，后 3 字节按网卡 GUID 派生 | `GetAdaptersAddresses`、`GetAdaptersInfo`、`GetIfTable`、`GetIfEntry`、`GetIfTable2[Ex]`、`GetIfEntry2[Ex]` |
| 账号名 | 小写字母开头、6 位 `[a-z0-9]` | `GetUserNameW/A`、`GetUserNameExW/A(NameSamCompatible)`、`LookupAccountSidW/A`（真 SID → 派生名）、`LookupAccountNameW/A`（派生名 → 派生 SID）；环境变量 `USERNAME` |
| 账号 SID | `S-1-5-21-…-1001`（文本与二进制两种形式） | `ConvertSidToStringSidW/A`（真 SID 的文本 → 派生文本）、`LookupAccountSidW/A`（派生 SID → 派生名 + 派生域）、`LookupAccountNameW/A`（派生名 → 派生 SID）、`GetTokenInformation`（TokenUser 等 → 派生 SID）、`LsaLookupSids` / `LsaLookupSids2` / `LsaLookupNames2`（.NET 使用的 LSA 直接路径） |
| 主板 / BIOS / 内存条序列号、系统 UUID | 与主机同长度的序列号；UUID 为 16 字节 | `GetSystemFirmwareTable('RSMB')` 返回的 SMBIOS 表：Type 1 的序列号与 UUID、Type 2 的序列号、Type 17 的序列号，再按值替换其它结构里相同的字符串（本机的机箱序列号与系统序列号是同一个） |
| 物理磁盘序列号 | 与主机同长度 | `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` 的 `STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset` 指向的字符串 |

### 为什么改在 NT 层

第一轮挂的是 `RegQueryValueExW`、`GetVolumeInformationW` 这类 Win32 入口。审阅发现同一个值还有别的路：

- `reg query <键>`（不带 `/v`）走 `RegEnumValueW → NtEnumerateValueKey`，原来会把主机的 MachineGuid 原样列出来；`RegQueryValueExA`、`RegGetValueA` 也没挂。
- Node 的 `fs.stat().dev`、`GetFileInformationByHandle`、`GetVolumeInformationByHandleW` 都不经过 `GetVolumeInformationW`，原来拿到的是主机卷号。Claude Code 就是 Node 程序。

这些入口最终都落到同一个 NT 调用，所以现在只在那一层改写：注册表值在 `NtQueryValueKey` / `NtEnumerateValueKey` 里按键名 + 值名应答（按调用方请求的信息类别和缓冲区大小返回系统同样的状态码与长度，"先问长度再取值"的两段式调用照常工作）；卷号在 `NtQueryVolumeInformationFile` 里改写。`GetVolumeInformationW/A` 的单独挂钩已删除，避免同一个值被改两次。

### 卷序列号：按真实卷号派生

NT 层只知道"是哪个卷"，不知道调用方用的路径，所以派生值以该卷的**真实序列号**为键：`派生 = derive(账号键, 'V', 真实序列号)`。好处是所有通往同一卷的路都一致——盘符、`NULL`（当前盘）、挂在 `C:\mnt\data` 上的卷、打开的文件句柄——而且挂载点卷与 `C:` 自然分开。

64 位卷号（`FileIdInformation`）的低 32 位与 `vol` 显示的值一致，高 32 位另行派生，与 NTFS 的实际关系相同。

**按路径与按句柄必须一致（2026-11-16 修复）**：Windows 11 24H2 起，Node（libuv）的 `fs.stat()` 优先用 `GetFileInformationByName(FileStatBasicByNameInfo)` 按路径读取，底层是 `NtQueryInformationByName(FileStatBasicInformation)`，结果里偏移 80 处带 64 位卷号；`fs.fstat()` 仍按句柄走 `FileFsVolumeInformation`。原先只改写了句柄路线，同一个文件的 `stat().dev` 是主机真实值、`fstat().dev` 是派生值，Claude 读取会话文件时的"同一文件"校验失败，报"链接或占位符"。现在 `NtQueryInformationByName` 也被挂钩，类别 77 无论按路径还是按句柄都用 `volume_serial64` 改写，低 32 位与 `FileFsVolumeInformation` 的派生值相同。Win10 没有该类别，因此在 Win10 上的测试发现不了这个问题；集成测试新增了 `stat(execPath).dev == fstat(fd).dev` 的断言，需要在 24H2 以上的机器上运行才有意义。

`derive` 是带账号键的 FNV-1a 加 murmur3 收尾混淆，Rust（`identity.rs::derive`）与 C（`idguard.c::derive`）逐字节一致。用带键的非线性混淆而不是"基值异或"，是因为异或方案下同一台机器上任何账号的 `serial(C) ^ serial(D)` 都相等，可以据此把账号串起来，甚至认出 Hydra 本身；单元测试 `volume_relations_do_not_link_accounts` 钉住这一点，`derive_matches_the_guard` 钉住一组在真实沙箱里观察到的值。

### MAC：按网卡 GUID 派生

第一轮按网卡在列表中的**序号**派生，有两个问题：`GetAdaptersAddresses` 与 `GetAdaptersInfo` 列出的网卡集合不同，同一块网卡在两个接口里序号不同、MAC 也不同；插拔 VPN / 虚拟网卡后序号整体错位，所有账号的 MAC 一起变。现在后 3 字节由 `derive(账号 MAC, 'M', 网卡 GUID)` 得出：同一块网卡在所有接口、所有重启之间都是同一个地址。只改长度为 6 的物理地址，隧道等其他长度的地址保持原样。

### 主机名与账号

主机名不只出现在 `GetComputerName` 里：

- 不在域里的机器上，`USERDOMAIN`、`USERDOMAIN_ROAMINGPROFILE` 等于计算机名，`LOGONSERVER` 是 `\\计算机名`。启动器把它们和 `COMPUTERNAME` 一起换掉（`identity::identity_env`）；在域里时它们是域与域控，所有账号本来就共用，保持不变。
- 本地账号的"域"就是计算机名：`whoami` 打印 `主机名\用户`。`LookupAccountSid/Name`、`GetUserNameEx(NameSamCompatible)` 把等于主机名的域换成派生名，缓冲区不够时按系统的方式报 `ERROR_INSUFFICIENT_BUFFER` / `ERROR_MORE_DATA` 和所需长度。
- 账号名走 `GetUserNameW/A`（注意它的长度**含**终止符，与 `LookupAccount*` 不含终止符的约定不同）和 `GetUserNameEx(NameSamCompatible)`；`USERNAME` 环境变量由启动器一并换掉。
- 账号 SID 的文本形式在 `ConvertSidToStringSidW/A` 里换（系统返回的字符串是 `LocalAlloc` 分配的，替换时按同样方式分配并释放原串）；`LookupAccountName` 拿到派生名时直接应答派生 SID，`LookupAccountSid` 拿到派生 SID 时直接应答派生名，真 SID 则调用系统查得名字后换成派生值。
- 这些查询的 `*Local` 变体（`LookupAccountSidLocalW/A`、`LookupAccountNameLocalW/A`）由 `sechost.dll` 导出、`advapi32` 不转发，.NET 的账号类走的是这一组，所以单独挂钩。
- **userenv 例外**：`GetUserProfileDirectoryW` 会用 `GetUserNameExW` / `ConvertSidToStringSidW` 得到账号再去打开 `C:\Users\<名>`。如果它也拿到派生账号，配置文件目录就不存在，函数失败并将长度留成 0 —— Node 的 `os.userInfo()` 会因此报 `ENOMEM`。防护 DLL 用 `RtlPcToFileHeader` 判断调用方：来自 `userenv.dll` 的调用返回主机自己的答案，其余调用仍返回派生值。

### 账号 SID：二进制形式

只改文本不够：`whoami /user` 和 .NET 的账号类拿到的是令牌里的 SID 字节，自己把它格式化成字符串，不经过 `ConvertSidToStringSid`。所以第四轮改在令牌查询这一层：

- `GetTokenInformation`：`TokenUser`、`TokenOwner`、`TokenPrimaryGroup` 里的 SID 和 `TokenGroups` / `TokenRestrictedSids` 列表里属于本账号的 SID，在调用方自己的缓冲区里原地换成派生 SID。派生 SID 与真实本机 SID 形状相同（`S-1-5-21-…-1001`，28 字节），替换不会移动后面的数据。
- `LsaLookupSids` / `LsaLookupSids2`：查 SID → 名字。输入里属于本账号的 SID（派生或真实）先换回真实 SID 让 LSA 能解析，返回后把这一项的名字与域名换成派生的；域名表里本机那一项的域名也换成派生计算机名。调用方用 `LsaFreeMemory` 释放的是 LSA 的块，名字指向进程内常量，不受影响。
- `LsaLookupNames2`：查名字 → SID。`域名\派生用户名` 先换成主机能解析的真实账号，返回的 SID 再换成派生 SID。
- .NET 的 `WindowsIdentity.Name` 读 `TokenUser` 后用 LSA 解析名字，所以这三处缺一不可；都不命中时行为与系统一致。
- userenv 同样豁免：它按令牌 SID 找配置文件，拿到派生 SID 会找不到。

结果是 `whoami /user`、`WindowsIdentity.Name` / `.User.Value`、`SecurityIdentifier.Translate` 两个方向全部报盒内账号（实测见下）。令牌本身仍带着主机 SID 供访问检查使用，改的只是"它报告什么"。

### WMI：盒内关闭

主板的序列号、BIOS 版本、产品 UUID、磁盘序列号还能经 WMI 读到，而 WMI 由盒外的 `WmiPrvSE.exe` 应答，进程内挂钩够不到。第三轮改为在盒子配置里 `append ClosedFilePath` 关闭 `C:\Windows\System32\wbem\*` 与 `C:\Windows\SysWOW64\wbem\*`（两个位数都要，32 位 `wmic.exe` 在 `SysWOW64` 下）。效果是盒内 `wmic`、`Get-CimInstance`、`Get-WmiObject`、`getmac.exe` 全部失败（实测 `Access is denied.`），而不是报出主机的值。

MUST 用 `append` 而不是 `set`：`set` 会覆盖已有的 `ClosedFilePath` 列表，把别的封闭路径一起打开。

### 固件与磁盘序列号

WMI 关掉以后，进程内还剩两条路能读到硬件序列号，第三轮都改了：

- `GetSystemFirmwareTable('RSMB')`：返回的是 `RawSMBIOSData`（8 字节头 + 结构表）和一块调用方自己的缓冲区。按结构类型找到序列号字符串（System 0x07、Baseboard 0x07、Memory Device 0x18），用 `derive(机器 GUID 文本, 'S', 原序列号)` 生成长度相同的序列号并**原地**覆盖；第二遍再按值替换其它结构里相同的字符串（本机 Type 3 机箱序列号与系统序列号相同）。Type 1 的 UUID（0x08 起 16 字节）按账号重新派生并置为 version 4 / RFC 4122 variant。只改内容、不改长度，所以字符串偏移不变；表尾如果带校验和（本机这张表的 Type 127 只有 4 字节，没有校验和字段），改完后重算。
- `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)`：`STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset` 指向缓冲区内的序列号字符串，同样按原长度原地覆盖。重叠（overlapped）调用此时缓冲区里还没有结果，不改。

### 账号浏览器：网页指纹

账号浏览器是每个账号一个 WebView2 窗口（独立数据目录、独立出口与时区）。网页看到的 Canvas、WebGL、字体测量、屏幕与硬件参数第四轮改成按账号派生：

- 实现方式：创建窗口时，通过 WebView2 窗口构建器的 `initialization_script` 注册一段脚本（`browser.rs` 的 `FINGERPRINT_JS`）。种子由账号 ID 派生，脚本里的每个值都由它决定。
- Canvas：`toDataURL` / `toBlob` 在副本画布上按"内容 + 账号"确定性地改几个像素的 1 个色阶；`getImageData` 同样处理。同一张图读两次结果一致（不会被"读取不稳定"识别），不同账号不一致，肉眼不可见。
- WebGL / GPU：`getParameter(UNMASKED_VENDOR_WEBGL)` 与 `getParameter(UNMASKED_RENDERER_WEBGL)` 按账号从一组常见 GPU 里选一组返回（NVIDIA / Intel / AMD 的 ANGLE 字符串），`WebGLRenderingContext` 与 `WebGL2RenderingContext` 都覆盖。
- 字体：字体本身装在机器上，无法按账号隐藏；改为给测量结果加确定性微扰——`measureText().width` 与 `getBoundingClientRect()` 的宽高偏移零点几像素（不足以影响布局），使基于文字宽度的字体探针在每个账号得到不同的哈希。
- 屏幕与硬件：`screen.width / height / availWidth / availHeight / colorDepth / pixelDepth` 从几组常见分辨率里按账号选一组（高度都在 1050 以上，不会出现窗口比屏幕还高），`navigator.hardwareConcurrency` 与 `deviceMemory` 同理。
- 所有覆盖都在 `try/catch` 里，失败时回退到真实实现；函数保留 `toString()` 的 `[native code]` 形式。
- 单元测试在 Node 里用最小的 canvas / screen / navigator 桩真正执行这段脚本：同一账号读两次一致、两个账号不同、元素宽度与文字宽度只偏移零点几像素；另有 `node --check` 语法检查。

### 其他配套

- 防护 DLL 对存在转发关系的函数在两个模块上都挂（`kernel32`/`kernelbase`、`advapi32`/`sechost`、`secur32`/`sspicli`），但同一地址只挂一次：转发导出经 `GetProcAddress` 会解析到同一个地址，重复挂钩会叠在自己身上。
- `InjectDllMain` 可能被 Sandboxie 调用不止一次；第二次执行时防护已经装好，会把派生值当成主机的值读走。入口用 `InterlockedCompareExchange` 只放行第一次。
- 所有 `Hydra*` 值由 Rust 侧一次写全；缺 `HydraMachineGuid` 时防护 DLL 整体不启用。
- `InjectDll` / `InjectDll64` 每个值只当一个 DLL 路径，多个 DLL 要重复写多行；`set_injection` 先清空再逐个 `append`，回归测试 `every_guard_is_its_own_injection_line` 守着。DLL 文件名带内容哈希，手工改 ini 追加新路径而不清空旧项，会继续加载旧一代 DLL。
- **发布版必须带 32 位防护**：缺 x86 MSVC 工具链时，`build.rs` 在 release 构建里直接失败（debug 构建仍只警告）。否则盒内所有 32 位程序会报主机标识，也不受中继端口限制。

代码位置：`app/src-tauri/src/identity.rs`（派生）、`app/src-tauri/src/idguard.c`（改写）、`app/src-tauri/src/sandbox.rs`（写入沙箱配置与注入）、`app/src-tauri/src/launcher.rs`（环境变量）。

## 已验证

2026-11-13 第三、四轮，本机 Windows + Sandboxie-Plus，账号 `hydra-identity-test`（沙箱 `Hydra_e32311b88f`）。主机同一时刻：MachineGuid `9ce867b7-…`、主机名 `LAPTOP-UUCIGDOF`、用户 `24779`、用户 SID `S-1-5-21-1878996900-2321732902-594864897-1001`、BIOS/主板序列号 `PF31RA14`、C: 磁盘序列号 `001B_448B_4807_6193.`、C: 卷号 `04EF-9568`。

集成测试 `CLAUDE_HYDRA_ROOT=<scratch> cargo test --lib sandboxie_identity -- --ignored --nocapture` 在盒内执行以下命令并逐条断言，全部通过：

| 读法 | 盒内结果 |
|---|---|
| `reg query …\Cryptography /v MachineGuid`、枚举同一键 | 派生值；枚举结果不含主机值 |
| `hostname` / `whoami` | `DESKTOP-F1JX9W6` / `desktop-f1jx9w6\oqvh7l` |
| `vol C:` / `vol D:` | 各自的派生值，互不相同，不等于主机值 |
| `ipconfig /all` | 全部网卡 `AA-6C-7B-…`，互不相同 |
| Node `os.hostname()`、`fs.statSync('C:/').dev`、`os.networkInterfaces()` | 派生值；MAC 与 `ipconfig` 一致 |
| Node `os.userInfo().username` | `oqvh7l` |
| `%USERNAME%` / `%USERDOMAIN%` | `oqvh7l` / `DESKTOP-F1JX9W6` |
| 原生 `GetUserNameW` | `True`，长度 7（6 字符 + 终止符），`oqvh7l` |
| 原生 `LookupAccountNameW`（派生名） | 派生 SID `S-1-5-21-1372292228-…`，域 `DESKTOP-F1JX9W6`；长度探测要 28 字节 |
| 原生 `LookupAccountSidW` / `LookupAccountSidLocalW`（真 SID 的文本 → 二进制） | 名字 `oqvh7l`，域 `DESKTOP-F1JX9W6` |
| 原生 `ConvertSidToStringSidW`（真 SID） | 派生 SID 文本 |
| 原生 `GetTokenInformation(TokenUser)` | 令牌里的 SID 是派生 SID `S-1-5-21-1372292228-…` |
| `whoami /user` | `desktop-f1jx9w6\oqvh7l`，SID 是派生 SID |
| .NET `WindowsIdentity.Name` / `.User.Value` | `DESKTOP-F1JX9W6\oqvh7l` / 派生 SID；`SecurityIdentifier.Translate` 两个方向都返回派生值 |
| `GetSystemFirmwareTable('RSMB')` 的字符串 | BIOS/主板序列号 `PF31RA14` → `JBWVL4ER`，内存条序列号同样改写；Type 3 机箱序列号按值替换；主机序列号一个都不出现 |
| `DeviceIoControl(C:, IOCTL_STORAGE_QUERY_PROPERTY)` | 磁盘序列号 `001B_448B_4807_6193.` → 同长度的 `0S9YH7PCB5D87RUKA6ER` |

另有一个 WMI 测试 `sandboxie_wmi_reports_no_hardware`：盒内 `wmic bios/baseboard/diskdrive/csproduct/computersystem`、32 位 `SysWOW64` 的 `wmic`、`Get-CimInstance Win32_BIOS`、`getmac` 全部失败（`Access is denied.`），并且主机的 BIOS / 主板 / 磁盘 / 内存序列号与主机名一个都没有出现。

网页指纹由单元测试覆盖：`fingerprint_script_follows_the_account`（同一账号稳定、不同账号不同、覆盖所列 API）、`fingerprint_script_parses_as_javascript`（`node --check`）、`fingerprint_script_changes_what_the_page_measures`（在 Node 的 canvas / screen / navigator 桩上真正执行脚本：同一账号读两次一致，两个账号的像素哈希不同，元素与文字测量只偏移零点几像素，屏幕与核数落在允许集合里）。脚本还在**无头 Edge**（与 WebView2 同一 Blink 引擎）里实际运行验证过：种子 12345 与 777 的 canvas 哈希与 `getImageData` 像素不同，同一画布连续读两次一致，`getBoundingClientRect` 只偏移 0.01，`measureText` 偏移在 0.016 以内，屏幕 / 核数 / WebGL 渲染器均按账号变化。这一步抓到一个真实问题：`ImageData.data` 是只读的，最初"整体赋值"的噪声写法在真实浏览器里被静默丢弃，改为原地修改后才生效。本轮另用独立发布构建的两个真实 WebView2 账号窗口加载本地测试页。页面第一段内联脚本在系统时区和指定 Asia/Tokyo 两条路径都读到预期的屏幕、核数和时区；零尺寸保持为零，白色画布的 PNG 两种导出一致，解码色值在 254–255。该检查为本地集成验收，不包含在线登录。

同一次运行在盒外读 MachineGuid、序列号仍是主机原值：防护只作用于盒内进程。全部单元测试与其余需要 Sandboxie 的集成测试同样通过。

启动器在账号进程没进沙箱、或防护 DLL 没加载时会关掉它并报错（`launcher.rs` 的 `confirm_boxed`），所以沙箱配置写错不会静默失效。

## 没有覆盖到的部分

先区分两类：**盒外应答**的（防护 DLL 进不去，只能上虚拟机）和**能改但有意不改**的。

盒外应答，值与主机一致：

- **DHCPv6 DUID**：`ipconfig /all` 的 DUID 行由盒外提供，尾部是主机首块网卡的地址。
- **虚拟化层本身**：CPU 型号、核心数、内存大小、显卡与驱动版本来自内核与硬件，进程内改不了。

能在进程内改，但有意不改或改不彻底：

- **令牌本身与访问检查**：`GetTokenInformation` 与 LSA 查询现在报派生 SID，但令牌实际携带的仍是主机 SID，访问控制（文件 ACL、`HKU\<SID>`、组策略）照旧按真实 SID 判断。直接调用 `NtQueryInformationToken`（绕过 `GetTokenInformation`）的程序也仍会看到真实 SID。
- **`USERPROFILE` 与路径**：用户名出现在 `C:\Users\24779\…`、账号数据目录、当前工作目录里。只改 API 而路径不变会造出明显自相矛盾的环境，所以路径保持主机用户；`userenv` 也因此按主机账号应答（见上）。
- **账号浏览器以外的浏览器**：网页指纹脚本只注入 Hydra 打开的账号浏览器（WebView2）。用户自己打开的 Chrome / Edge、其他 WebView2 窗口、Claude Code 命令行里的 Node 网络栈都不经过它；这些环境的 Canvas / WebGL 仍是主机的。
- **WebGPU 与 Client Hints**：`navigator.gpu`（WebGPU adapter 信息）与 `navigator.userAgentData`（Client Hints 的高熵字段）本轮没有覆盖，仍是真实值；使用它们的站点能看到主机 GPU / 平台。
- **字体的"存在性"**：脚本扰动的是测量结果，不是字体列表。`document.fonts.check` 与基于渲染的字体枚举仍能看到机器上真实安装的字体集合；只是每次测量得到的宽度按账号不同，指纹哈希因此不同。
- **网页指纹本身的可探测性**：覆盖是脚本层的，`Function.prototype.toString` 已伪装成原生实现，但深度检测（例如在 Worker / iframe / WASM 里做同样的测量并比对）仍可能发现主线程与其它上下文不一致；这是所有脚本级指纹伪装共有的边界。
- **SCSI pass-through**（`IOCTL_SCSI_PASS_THROUGH` 一类的裸设备查询）也能拿到磁盘序列号，本轮没有挂钩。
- **WMI 整体不可用**：盒内 WMI 查询全部失败，这与真实机器不同。能读到硬件序列号远比"WMI 报错"更可疑，所以选前者；但依赖 WMI 的程序在盒内会失败，这是 Sandboxie 方案下无法避免的取舍。
- **卷创建时间、卷对象 ID**（`FileFsVolumeInformation.VolumeCreationTime`、`FileFsObjectIdInformation`）、`NtQueryMultipleValueKey`：较少被用作指纹，本轮没有改。
- **理解 B 本身**：共用内核，见上。

## 尚未完成的内容

1. **虚拟机级隔离（理解 B）**：没有。
2. **网页指纹的剩余面**：WebGPU、Client Hints、DOM 字体存在性，以及 Worker / iframe 内的一致性，见上一节。
3. **不开沙箱时的强制代理**：没有。不开沙箱时只有启动前的连通性核对和代理环境变量两条约束，自带网络栈或忽略代理变量的进程仍能直连；要做到与沙箱等价需要管理员权限下的 WFP 过滤或等价的内核层拦截。
4. **令牌级 SID 替换与 `%USERPROFILE%` 路径**：不打算在 Sandboxie 方案内处理，见上一节。

## 本轮改动（第三、四轮）

- 账号：`GetUserNameW/A`、`GetUserNameEx(NameSamCompatible)` 的用户名，`LookupAccountSid/Name` 及其 `*Local` 变体，`ConvertSidToStringSid`，以及 `USERNAME` 环境变量；`userenv` 的调用按主机账号应答，避免 `GetUserProfileDirectoryW` 失败。
- 账号 SID 的二进制形式：`GetTokenInformation`（TokenUser / TokenOwner / TokenPrimaryGroup / TokenGroups / TokenRestrictedSids）、`LsaLookupSids` / `LsaLookupSids2` / `LsaLookupNames2`，.NET 与 `whoami /user` 因此全部报派生账号。
- 固件与磁盘：改写 SMBIOS 表（Type 1/2/17 序列号、Type 1 UUID、同值字符串）与 `IOCTL_STORAGE_QUERY_PROPERTY` 的磁盘序列号，均在原缓冲区原地、原长度改写。
- WMI：盒内关闭 `System32\wbem` 与 `SysWOW64\wbem`（`append ClosedFilePath`），所有 WMI 查询失败而不是泄漏主机硬件。
- 网页指纹：账号浏览器注入按账号派生的 Canvas / WebGL / GPU / 字体测量 / 屏幕 / CPU 内存覆盖脚本，并有 Node 桩上的功能测试。
- `InjectDllMain` 只执行一次，避免 Sandboxie 二次调用把派生值当成主机值。
- 集成测试新增账号探测（原生 API、令牌、.NET 与 LSA）、SMBIOS 与磁盘序列号断言，以及独立的 WMI 测试。
