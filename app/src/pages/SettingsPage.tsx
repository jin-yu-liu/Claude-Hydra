import { Copy, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Group, Page, PageHeader, Row } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/toast";
import { api, errorText, type AppInfo } from "@/lib/api";
import type { ThemeMode } from "@/lib/theme";
import { cn } from "@/lib/utils";

interface Props {
  info: AppInfo | null;
  reloadInfo: () => Promise<void>;
  theme: ThemeMode;
  onThemeChange: (m: ThemeMode) => void;
  onInstallChanged: () => void;
}

function KeyValue({ k, v }: { k: string; v?: string | null }) {
  return (
    <div className="flex gap-4 px-4 py-2.5 text-[12.5px]">
      <span className="w-24 shrink-0 text-muted">{k}</span>
      <span className="selectable min-w-0 break-all font-mono text-[11.5px] leading-[18px] text-fg-2">{v || "—"}</span>
    </div>
  );
}

const themes: { id: ThemeMode; label: string }[] = [
  { id: "system", label: "跟随系统" },
  { id: "light", label: "浅色" },
  { id: "dark", label: "深色" },
];

export function SettingsPage({ info, reloadInfo, theme, onThemeChange, onInstallChanged }: Props) {
  const toast = useToast();
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => setPath(info?.claudePath ?? ""), [info?.claudePath]);

  const act = async (key: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(key);
    try {
      await fn();
      if (done) toast(done);
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(null);
      reloadInfo();
    }
  };

  const install = info?.install;

  return (
    <Page>
      <PageHeader title="设置" subtitle="外观、启动方式与 Claude 桌面端的位置。" />
      <div className="space-y-5 px-5">
        <Group label="外观">
          <Row label="主题" hint="跟随系统时会随系统的浅色 / 深色自动切换。">
            <div className="flex rounded-lg bg-pill p-0.5">
              {themes.map((t) => (
                <button
                  key={t.id}
                  onClick={() => onThemeChange(t.id)}
                  className={cn(
                    "h-6 rounded-md px-3 text-[12.5px] active:!scale-100",
                    theme === t.id ? "bg-card font-medium text-fg shadow-edge dark:bg-white/[.12]" : "text-muted hover:text-fg",
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </Row>
        </Group>

        <Group label="启动">
          <Row label="开机时启动到托盘" hint={info?.platform === "windows" ? "登录系统后在后台运行，托盘图标可一键切换账号。" : "目前仅 Windows 支持。"}>
            <Switch
              checked={!!info?.autostart}
              disabled={!info || info.platform !== "windows" || busy === "auto"}
              onCheckedChange={(v) => act("auto", () => api.setAutostart(v))}
            />
          </Row>
          {info?.platform === "windows" && (
            <Row label="登录与链接路由" hint="注册后在 Windows 默认应用中把 Claude-Hydra 设为默认浏览器（以及 claude 链接）。之后 Claude 打开的谷歌登录等链接会进入该账号的专属浏览器，与账号同一出口 IP 和时区；其他链接仍交给你原来的浏览器。">
              <Button variant="outline" size="sm" disabled={busy === "router"} onClick={() => act("router", () => api.setupLoginRouter(), "已注册。请在系统设置中把 Claude-Hydra 设为默认浏览器。")}>
                设置
              </Button>
            </Row>
          )}
        </Group>

        <Group label="网络保护">
          <Row label="额外账号必须绑定代理环境" hint="开启后，没有绑定带代理节点的环境的额外账号会拒绝启动，账号专属浏览器也不会打开，避免误用本机网络直连。系统默认账号不受影响。">
            <Switch
              checked={!!info?.requireEnvironment}
              disabled={!info || busy === "require"}
              onCheckedChange={(v) => act("require", () => api.setRequireEnvironment(v))}
            />
          </Row>
        </Group>

        <Group label="Claude 桌面端">
          {info?.installError && <div className="px-4 py-3 text-[12.5px] text-danger">{info.installError}</div>}
          {install && (
            <div className="py-1">
              <KeyValue k="类型" v={install.kind === "Msix" ? "Microsoft Store 版" : install.kind === "App" ? "Claude.app" : "安装程序版"} />
              {install.version && install.version !== "unknown" && <KeyValue k="版本" v={install.version} />}
              <KeyValue k="程序" v={install.exe ?? install.family} />
              <KeyValue k="默认数据目录" v={install.defaultProfile} />
            </div>
          )}
          <div className="flex gap-2 px-4 py-3">
            <Input
              placeholder={info?.platform === "macos" ? "/Applications/Claude.app（留空为自动查找）" : "C:\\…\\Claude.exe（留空为自动查找）"}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="font-mono text-xs"
            />
            <Button
              variant="outline"
              disabled={busy === "path"}
              onClick={() =>
                act(
                  "path",
                  async () => {
                    await api.setClaudePath(path.trim() || null);
                    onInstallChanged();
                  },
                  path.trim() ? "已使用指定的路径。" : "已恢复自动查找。",
                )
              }
            >
              {busy === "path" && <Loader2 className="animate-spin" />}
              应用
            </Button>
          </div>
        </Group>

        <Group label="数据与诊断">
          <div className="py-1">
            <KeyValue k="根目录" v={info?.storageRoot} />
            <KeyValue k="设置文件" v={info?.settingsPath} />
          </div>
          <Row label="诊断信息" hint="包含版本、路径与各账号运行状态，系统用户名已自动脱敏。">
            <Button
              variant="outline"
              size="sm"
              disabled={busy === "doctor"}
              onClick={() =>
                act(
                  "doctor",
                  async () => {
                    const text = await api.diagnostics();
                    await navigator.clipboard.writeText(text);
                  },
                  "诊断信息已复制到剪贴板。",
                )
              }
            >
              {busy === "doctor" ? <Loader2 className="animate-spin" /> : <Copy />}
              复制
            </Button>
          </Row>
        </Group>

        {info?.platform === "windows" && (
          <Group label="沙箱设置">
            <Row label="沙箱管理器" hint="查看沙箱、运行中的程序和高级设置。">
              <Button variant="outline" size="sm" disabled={busy === "sandbox"} onClick={() => act("sandbox", api.openSandboxManager)}>
                打开沙箱管理
              </Button>
            </Row>
          </Group>
        )}
      </div>
    </Page>
  );
}
