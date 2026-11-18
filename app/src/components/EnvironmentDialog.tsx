import { useEffect, useRef, useState } from "react";
import { api, errorText, type EnvironmentInput, type ExitInfo, type ExitRule } from "@/lib/api";
import { EXIT_RULES, LOCALES, emptyEnvironment } from "@/lib/environment";
import { Switch } from "./ui/switch";
import { NodeConfigForm } from "./NodeConfigForm";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Input, Select, Textarea } from "./ui/input";

const IS_MAC = navigator.userAgent.includes("Mac");
/** The isolation switch keeps its wire value; only what it means differs per platform. */
const ISOLATION_NAME = IS_MAC ? "macOS 沙盒" : "Sandboxie-Plus";

interface Props {
  open: boolean;
  /** Existing environment id, or null to create a new one. */
  id: string | null;
  initial?: EnvironmentInput;
  /** Exit timezone already confirmed for the saved node, if any. */
  detectedTimezone?: string | null;
  /** Exit the saved rule is bound to. */
  exitBaseline?: ExitInfo | null;
  onClose: () => void;
  onSaved: (id: string) => void;
}

function Line({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[88px_1fr] items-center gap-3 px-4 py-2">
      <span className="text-[12.5px] text-fg-2">{label}</span>
      <div className="flex min-w-0 items-center gap-2">{children}</div>
    </div>
  );
}

/** Create or edit a reusable environment: network, timezone, language and advanced launch options. */
const place = (x: ExitInfo) => [x.country, x.region, x.city].filter(Boolean).join(" ");

export function EnvironmentDialog({ open, id, initial, detectedTimezone, exitBaseline, onClose, onSaved }: Props) {
  const [env, setEnv] = useState<EnvironmentInput>(emptyEnvironment);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [sandbox, setSandbox] = useState<{ ok: boolean; text: string } | null>(null);
  const [baseline, setBaseline] = useState<string | null>(null);
  const [rebinding, setRebinding] = useState(false);
  const errorRef = useRef<HTMLParagraphElement>(null);

  // The error sits below every section; bring it into view or a failed save looks like a dead button (#5).
  useEffect(() => {
    if (error) errorRef.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [error]);

  useEffect(() => {
    if (!open) return;
    setEnv(initial ? { ...emptyEnvironment(), ...structuredClone(initial) } : emptyEnvironment());
    setError("");
    setBaseline(exitBaseline ? `${exitBaseline.ip}${place(exitBaseline) ? `（${place(exitBaseline)}）` : ""}` : null);
    api.sandboxStatus().then((dir) => setSandbox({ ok: true, text: IS_MAC ? "已检测到 macOS 沙盒（Seatbelt / sandbox-exec）" : `已检测到 Sandboxie-Plus：${dir}` }), (e) => setSandbox({ ok: false, text: errorText(e) }));
  }, [open, initial, exitBaseline]);

  const rebind = async () => {
    if (!id) return;
    setRebinding(true);
    setError("");
    try {
      setBaseline(await api.rebindExit(id));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setRebinding(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      onSaved(await api.saveEnvironment(id, env));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={id ? "编辑环境配置" : "新建环境配置"}
      description="保存后可在任意账号中选择使用；修改会作用于所有使用它的账号。"
      className="max-w-[600px] bg-bg"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>取消</Button>
          <Button onClick={save} disabled={saving || !env.name.trim()}>{saving ? "保存中…" : "保存"}</Button>
        </>
      }
    >
      <div className="space-y-5">
        <section>
          <div className="group-label">基础</div>
          <div className="list-card">
            <Line label="名称">
              <Input aria-label="环境名称" value={env.name} maxLength={40} autoFocus placeholder="例如：东京住宅 IP" onChange={(e) => setEnv({ ...env, name: e.target.value })} />
            </Line>
            <Line label="窗口语言">
              <Select aria-label="窗口语言" value={env.locale} onChange={(e) => setEnv({ ...env, locale: e.target.value })}>
                {LOCALES.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
              </Select>
            </Line>
          </div>
        </section>

        <section>
          <div className="group-label">网络与时区</div>
          <NodeConfigForm subscription={env.clashSubscription} onSubscriptionChange={(clashSubscription) => setEnv(e => ({ ...e, clashSubscription }))} idPrefix="env-node" node={env.node} onNodeChange={(node) => setEnv((e) => ({ ...e, node }))}
            timezone={env.timezone} onTimezoneChange={(timezone) => setEnv({ ...env, timezone })}
            detectedTimezone={JSON.stringify(env.node) === JSON.stringify(initial?.node ?? null) ? detectedTimezone : null}
            lastCheck={env.lastCheck} onLastCheckChange={(lastCheck) => setEnv((e) => ({ ...e, lastCheck }))} />
        </section>

        <section>
          <div className="group-label">出口保护与隔离</div>
          <div className="list-card">
            <Line label="出口规则">
              <Select aria-label="出口规则" value={env.exitRule} disabled={!env.node} onChange={(e) => setEnv({ ...env, exitRule: e.target.value as ExitRule })}>
                {EXIT_RULES.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
              </Select>
            </Line>
            {env.node && env.exitRule && (
              <div className="flex items-center gap-2 px-4 pb-2 pl-[116px] text-[11.5px] text-muted">
                <span className="min-w-0 flex-1">{baseline ? `已绑定出口 ${baseline}` : "尚未绑定：第一次通过检测的出口会成为基准。"}</span>
                {id && JSON.stringify(env.node) === JSON.stringify(initial?.node ?? null) && (
                  <Button variant="outline" size="sm" disabled={rebinding} onClick={rebind} title="以节点当前出口为新基准，并恢复被切断的账号">
                    {rebinding ? "检测中…" : "重新绑定"}
                  </Button>
                )}
              </div>
            )}
            <Line label="受限地区出口">
              <Switch checked={env.allowCn} onCheckedChange={(allowCn) => setEnv({ ...env, allowCn })} label="允许不支持地区的出口" />
              <span className="text-[11.5px] text-muted" title="中国大陆、香港、澳门、俄罗斯、白俄罗斯、伊朗、朝鲜、古巴、叙利亚">{env.allowCn ? "允许" : "拦截 Claude 不提供服务的地区（推荐）"}</span>
            </Line>
            <Line label="独立 Code">
              <Switch checked={env.separateCode || env.isolation === "sandboxie"} disabled={env.isolation === "sandboxie"} onCheckedChange={(separateCode) => setEnv({ ...env, separateCode })} label="每个账号使用独立的 Claude Code 登录与配置" />
              <span className="text-[11.5px] text-muted">{env.isolation === "sandboxie"
                ? "沙箱隔离时强制开启：共用 ~/.claude.json 会让各沙箱报出同一个 Claude Code 设备 ID"
                : env.separateCode ? "每个账号有自己的 Claude Code 登录、配置与会话目录" : "与本机的 Claude Code 共用登录和会话（~/.claude）"}</span>
            </Line>
            <Line label="沙箱隔离">
              <Switch checked={env.isolation === "sandboxie"} disabled={!sandbox?.ok && env.isolation !== "sandboxie"} onCheckedChange={(v) => setEnv({ ...env, isolation: v ? "sandboxie" : "" })} label={IS_MAC ? "在 macOS 沙盒中运行" : "在 Sandboxie-Plus 沙箱中运行"} />
              <span className="text-[11.5px] text-muted">{env.isolation === "sandboxie" ? `在 ${ISOLATION_NAME} 中运行` : "不使用沙箱"}</span>
            </Line>
            <p className="px-4 pb-3 text-[11.5px] leading-relaxed text-muted">
              {env.isolation === "sandboxie"
                ? (IS_MAC
                  ? "启动前用 macOS 的 Seatbelt 沙盒验证：沙盒内只能连接本机回环（中继），直连外部地址会被内核拒绝，验证不通过就不启动。账号浏览页的 Canvas / WebGL / GPU / 字体测量 / 屏幕等网页指纹按账号派生（尽力而为，需要 Claude 提供调试端口，失败会记录日志）。注意：主机名、网卡 MAC、IOPlatformUUID、序列号等系统级硬件标识仍与主机相同——macOS 不像 Sandboxie 那样能按进程改写这些内核值，只有虚拟机才能完全隔离。"
                  : "沙箱中只允许连接本账号的本地中继，任何绕过代理的进程都会断网；文件和注册表写入留在沙箱内（账号数据目录除外）。沙箱内无法经本机 DNS 解析外部域名，域名只经代理解析。商店版会先复制一份到 Hydra 数据目录再装入沙箱（首次较慢）；系统默认账号不能使用环境。启动后会核实 Claude 确实在沙箱中运行，否则立即关闭。")
                : "不用沙箱时：Claude 与它启动的工具都经本地中继出网（无直连回退），出口不合规则时会自动断网；但忽略代理设置的程序仍可能直连。"}
              {sandbox && !sandbox.ok && <span className="block text-warn">{sandbox.text}</span>}
            </p>
          </div>
        </section>

        <section>
          <div className="group-label">高级</div>
          <div className="list-card">
            <div className="px-4 py-3">
              <div className="mb-1.5 text-[12.5px] font-medium text-fg-2">额外启动参数</div>
              <Input aria-label="额外启动参数" className="font-mono text-xs" placeholder="--disable-gpu" value={env.args} onChange={(e) => setEnv({ ...env, args: e.target.value })} />
            </div>
            <div className="px-4 py-3">
              <div className="mb-1.5 text-[12.5px] font-medium text-fg-2">环境变量</div>
              <Textarea aria-label="环境变量" rows={3} placeholder={"每行一个：名称=值\n设置代理节点后，代理相关变量由 Hydra 管理"} value={env.env} onChange={(e) => setEnv({ ...env, env: e.target.value })} />
            </div>
          </div>
        </section>

        {error && <p ref={errorRef} className="selectable whitespace-pre-wrap rounded-xl bg-danger-soft px-4 py-3 text-[12.5px] text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}
