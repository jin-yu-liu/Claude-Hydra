import { useEffect, useState } from "react";
import { Group } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { AccountPicker } from "@/components/AccountPicker";
import { api, errorText, type Profile, type SessionPreview } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Copies Desktop Claude Code session indexes from one account to another (never moves or overwrites). */
export function CodeSessionMigration({ profiles, source, setSource }: { profiles: Profile[] | null; source: string; setSource: (source: string) => void }) {
  const [target, setTarget] = useState("");
  const [preview, setPreview] = useState<SessionPreview | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  const load = async () => {
    setPreview(null); setStatus("");
    if (!source || source === target) return;
    setBusy(true);
    try {
      const next = await api.sessionPreview(source, target);
      setPreview(next);
      setPicked(old => new Set(next.sessions.filter(s => !s.inTarget && old.has(s.id)).map(s => s.id)));
    }
    catch (e) { setStatus(errorText(e)); }
    finally { setBusy(false); }
  };
  useEffect(() => { void load(); }, [source, target]);

  const copyable = preview?.sessions.filter((s) => !s.inTarget) ?? [];
  const toggle = (id: string) => setPicked((old) => { const next = new Set(old); next.has(id) ? next.delete(id) : next.add(id); return next; });
  const copy = async () => {
    setBusy(true); setStatus("");
    try {
      const r = await api.copySessions(source, target, [...picked]);
      setPreview(await api.sessionPreview(source, target)); setPicked(new Set());
      setStatus(`已复制 ${r.copied} 个，跳过已存在 ${r.skipped} 个，失败 ${r.failed} 个${r.forked ? `，${r.forked} 个在两个账号里都继续过、已作为新会话迁入` : ""}。请打开目标账号确认会话列表。`);
    } catch (e) { setStatus(errorText(e)); }
    finally { setBusy(false); }
  };

  const blocked = !target || !preview || !!preview.targetProblem || preview.running;
  const allPicked = copyable.length > 0 && picked.size === copyable.length;

  if (!source) return (
    <Group label="选择来源账号">
      <div className="px-4 py-3"><AccountPicker label="查看可迁移会话" profiles={profiles} value="" onChange={setSource} /></div>
    </Group>
  );
  return (
    <Group label={`${profiles?.find(p => p.id === source)?.name ?? source} · 本地 Claude Code 会话`}>
      <div className="px-4 py-2"><Button size="sm" variant="ghost" disabled={busy} onClick={() => {
        setSource(""); setTarget(""); setPreview(null); setPicked(new Set()); setStatus("");
      }}>← 返回账号列表</Button></div>
      <div className="grid grid-cols-[56px_1fr] items-start gap-3 px-4 py-3">
        <span className="pt-1.5 text-[12.5px] text-fg-2">复制到</span>
        <AccountPicker label="目标账号" profiles={profiles} value={target} exclude={source} disabled={busy} onChange={setTarget} />
      </div>
      {!preview && !status && <p className="px-4 py-2.5 text-[12px] text-muted">{"正在读取会话…"}</p>}

      {preview && (
        <>
          {(preview.running || preview.targetProblem) && (
            <div className="space-y-1 bg-warn-soft/60 px-4 py-2.5 text-[12px] text-warn">
              {preview.running && <p>目标账号正在运行。请先退出目标账号，再点“重新读取”。</p>}
              {preview.targetProblem && <p>{preview.targetProblem}</p>}
            </div>
          )}
          {preview.sessions.length === 0 ? (
            <p className="px-4 py-3 text-[12.5px] text-muted">来源账号没有本地 Claude Code 会话。普通聊天请使用导出文件续聊。</p>
          ) : (
            <div className="max-h-72 overflow-y-auto py-1">
              {preview.sessions.map((s) => (
                <label key={s.id} className={cn("flex cursor-pointer items-start gap-2.5 px-4 py-1.5 hover:bg-card-2", s.inTarget && "cursor-default opacity-55")}>
                  <input type="checkbox" className="mt-[3px]" disabled={s.inTarget || busy} checked={picked.has(s.id)} onChange={() => toggle(s.id)} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px]">
                      {s.title}
                      {s.inTarget && <span className="text-muted"> · 目标已存在</span>}
                    </span>
                    <span className="block truncate text-[11px] text-muted">
                      {s.cwd ?? "未记录工作目录"}
                      {s.cwd && !s.cwdExists && <span className="text-warn"> · 目录不存在</span>}
                      {s.lastActivityAt ? ` · ${new Date(s.lastActivityAt).toLocaleString()}` : ""}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
            <Button variant="ghost" size="sm" disabled={busy || !copyable.length} onClick={() => setPicked(allPicked ? new Set() : new Set(copyable.map((s) => s.id)))}>
              {allPicked ? "取消全选" : "全选可复制"}
            </Button>
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => void load()}>重新读取</Button>
            <span className="flex-1" />
            <Button size="sm" disabled={busy || blocked || !picked.size} onClick={copy}>{busy ? "处理中…" : `复制 ${picked.size} 个会话`}</Button>
          </div>
        </>
      )}
      {status && <p role="status" className="px-4 py-2.5 text-[12.5px] text-fg-2">{status}</p>}
    </Group>
  );
}
