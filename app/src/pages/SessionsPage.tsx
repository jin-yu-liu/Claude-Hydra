import { useEffect, useRef, useState } from "react";
import { ChevronDown, Folder, Search, Trash2, Upload } from "lucide-react";
import { AccountPicker } from "@/components/AccountPicker";
import { Page } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";
import { api, errorText, type CodeSession, type Profile, type TransferResult } from "@/lib/api";
import { readChats } from "@/lib/chatExport";

type Action = { type: "move"; ids: string[] } | { type: "import" } | { type: "empty" };
const imported = (id: string) => id.startsWith("import/") && id.split("/").length === 4;
const directory = (s: CodeSession) => imported(s.id) ? "导入的聊天" : s.cwd || "未记录工作目录";
const leaf = (path: string) => path.split(/[\\/]/).filter(Boolean).pop() || path;
const summary = (r: TransferResult) => `完成 ${r.copied} 条，` + (r.updated ? `更新到最新 ${r.updated} 条，` : "") + `已是最新 ${r.skipped} 条，失败 ${r.failed} 条。`
  + (r.forked ? `另有 ${r.forked} 条在两个账号里都继续聊过，已作为新会话迁入（标题带“来自”），目标账号原来的对话保持不变。` : "");

export function SessionsPage({ profiles }: { profiles: Profile[] | null }) {
  const [selected, setSelected] = useState("");
  const account = profiles?.find(p => p.id === selected) ?? profiles?.[0];
  return <Page><div className="space-y-3 px-5">
    {account ? <Library key={account.id} account={account} profiles={profiles ?? []} select={setSelected} />
      : <p className="text-sm text-muted">{profiles ? "还没有账号。" : "正在读取账号…"}</p>}
  </div></Page>;
}

function Library({ account, profiles, select }: { account: Profile; profiles: Profile[]; select: (id: string) => void }) {
  const toast = useToast();
  const [trash, setTrash] = useState(false);
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<CodeSession[] | null>(null);
  const [error, setError] = useState("");
  const [revision, refresh] = useState(0);
  const [collapsed, setCollapsed] = useState(new Set<string>());
  const [picking, setPicking] = useState(false);
  const [picked, setPicked] = useState(new Set<string>());
  const [action, setAction] = useState<Action | null>(null);
  const [target, setTarget] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [chat, setChat] = useState<{ title: string; turns: string[] } | null>(null);
  const [confirmRestart, setConfirmRestart] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let current = true;
    setRows(null); setError("");
    api.sessionPreview(account.id, "", trash).then(v => { if (current) setRows(v.sessions); })
      .catch(e => { if (current) setError(errorText(e)); });
    return () => { current = false; };
  }, [account.id, trash, revision]);

  const groups = new Map<string, CodeSession[]>();
  for (const row of rows ?? []) {
    const key = directory(row);
    const group = groups.get(key) ?? [];
    group.push(row); groups.set(key, group);
  }
  const needle = query.trim().toLocaleLowerCase();
  const matches = (s: CodeSession) => (s.title + " " + directory(s)).toLocaleLowerCase().includes(needle);
  const shown = (rows ?? []).filter(matches);
  const toggle = (ids: string[]) => setPicked(old => {
    const next = new Set(old), remove = ids.every(id => next.has(id));
    for (const id of ids) { if (remove) next.delete(id); else next.add(id); }
    return next;
  });
  const open = (next: Action) => {
    setAction(next);
    setTarget(next.type === "import" ? account.id : "");
  };
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); refresh(n => n + 1); }
    catch (e) { toast(errorText(e), "error"); }
    finally { setBusy(false); }
  };
  const targetProfile = profiles.find(p => p.id === target);
  // Desktop loads its session list at startup, so a running target must restart to see new sessions.
  const needsRestart = action?.type === "move" && !!targetProfile?.pid && action.ids.some(id => !imported(id));
  const submit = (restart = false) => run(async () => {
    if (action?.type === "move") {
      setConfirmRestart(false);
      toast(summary(await api.copySessions(account.id, target, action.ids, restart)) + (restart ? `已重启「${targetProfile?.name}」。` : ""));
      setPicked(new Set());
    } else if (action?.type === "import" && file) {
      toast(summary(await api.importChats(target, await file.text())));
      select(target); setTrash(false); setQuery("");
    } else if (action?.type === "empty") {
      await api.recycleSession(account.id, "empty"); toast("回收站已清空");
    }
    setAction(null);
  });
  const read = (s: CodeSession) => run(async () => {
    const raw = await api.readImport(account.id, s.id);
    setChat(readChats("[" + raw + "]")[0]);
  });
  return <>
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="切换账号" className="field w-auto max-w-48" value={account.id} disabled={busy} onChange={e => select(e.target.value)}>
        {profiles.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
      <label className="relative ml-auto min-w-32 flex-1">
        <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted" />
        <input className="field pl-8" aria-label="搜索会话" placeholder="搜索会话或工作目录" value={query} onChange={e => setQuery(e.target.value)} />
      </label>
      {!trash && <Button size="sm" variant="ghost" disabled={busy} onClick={() => { setPicking(!picking); setPicked(new Set()); }}>{picking ? "取消选择" : "选择"}</Button>}
      <Button size="sm" variant={trash ? "outline" : "ghost"} disabled={busy} onClick={() => { setRows(null); setTrash(!trash); setPicking(false); setPicked(new Set()); setQuery(""); }}>
        <Trash2 />{trash ? "返回会话" : "回收站"}
      </Button>
      <Button size="sm" variant="outline" disabled={busy} onClick={() => input.current?.click()}><Upload />导入聊天JSON</Button>
      <input ref={input} type="file" accept=".json,application/json" hidden onChange={e => {
        const chosen = e.currentTarget.files?.[0];
        e.currentTarget.value = "";
        if (chosen) { setFile(chosen); open({ type: "import" }); }
      }} />
    </div>
    {trash && <div className="flex items-center justify-between"><strong>回收站 · {account.name}</strong>
      <Button size="sm" variant="outline" disabled={busy || !rows?.length} onClick={() => open({ type: "empty" })}>彻底清空</Button></div>}
    {picking && <div className="flex items-center gap-3 text-sm">
      <Button size="sm" variant="ghost" disabled={!shown.length || busy} onClick={() => toggle(shown.map(s => s.id))}>全选搜索结果</Button>
      <Button size="sm" disabled={!picked.size || busy} onClick={() => open({ type: "move", ids: [...picked] })}>迁移所选（{picked.size}）</Button>
    </div>}
    {error && <p role="alert" className="text-sm text-danger">{error} <button onClick={() => refresh(n => n + 1)}>重试</button></p>}
    {!error && (!rows || !shown.length) && <p className="py-6 text-center text-sm text-muted">{!rows ? "正在读取会话…" : needle ? "没有匹配的会话。" : trash ? "回收站为空。" : "此账号暂无本地会话。"}</p>}
    {[...groups].map(([path, all]) => {
      const list = all.filter(matches);
      if (!list.length) return null;
      const folded = collapsed.has(path) && !needle;
      return <section key={path} className="list-card">
        {/* The fold button carries the row's padding, so the whole header left of "迁移整组" is its hit area. */}
        <div className="flex items-center gap-2 bg-card-2 pr-3">
          <button className="flex min-w-0 flex-1 items-center gap-2 rounded-[inherit] py-2 pl-3 text-left" aria-expanded={!folded} onClick={() => {
            const next = new Set(collapsed); if (next.has(path)) next.delete(path); else next.add(path); setCollapsed(next);
          }}>
            <ChevronDown className={`h-4 w-4 shrink-0 text-fg-2 ${folded ? "-rotate-90" : ""}`} /><Folder className="h-4 w-4 shrink-0 text-muted" />
            <span className="min-w-0"><strong className="block truncate text-sm">{leaf(path)}</strong>
              <span className="block truncate text-xs text-muted" title={path}>{path !== leaf(path) ? path + " · " : ""}{all.length} 个会话</span></span>
          </button>
          {!trash && <Button size="sm" variant="ghost" disabled={busy} onClick={() => open({ type: "move", ids: all.map(s => s.id) })}>迁移整组</Button>}
        </div>
        {!folded && list.map(s => <div key={s.id} className="flex items-center gap-2 px-4 py-2">
          {picking && <input aria-label={`选择 ${s.title}`} type="checkbox" checked={picked.has(s.id)} onChange={() => toggle([s.id])} />}
          <div className="min-w-0 flex-1"><div className="truncate text-[13px]" title={s.title}>{imported(s.id) && !trash
            ? <button onClick={() => read(s)} className="hover:underline">{s.title}</button> : s.title}</div>
            <small className="block truncate text-muted" title={s.model ?? undefined}>
              {s.lastActivityAt != null ? new Date(s.lastActivityAt).toLocaleString("zh-CN", {month:"2-digit", day:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit"}) : "时间未知"}
              {" · "}{s.model || "模型未知"}{" · "}{s.turns == null ? "轮数未知" : `${s.turns} 轮`}
            </small></div>
          {!trash && <Button size="sm" variant="outline" disabled={busy} onClick={() => open({ type: "move", ids: [s.id] })}>迁移</Button>}
          <Button size={trash ? "sm" : "iconSm"} variant="ghost" aria-label={trash ? "还原" : "删除"} title={trash ? "还原" : "移入回收站"} disabled={busy} onClick={() => run(async () => {
            await api.recycleSession(account.id, trash ? "restore" : "delete", s.id);
            setPicked(old => { const next = new Set(old); next.delete(s.id); return next; });
            toast(trash ? "已还原会话" : "已移入回收站");
          })}>{trash ? "还原" : <Trash2 />}</Button>
        </div>)}
      </section>;
    })}
    <Dialog open={!!action} onClose={() => { if (!busy) setAction(null); }}
      title={action?.type === "empty" ? "彻底清空回收站？" : action?.type === "move" ? `迁移 ${action.ids.length} 个会话` : "导入聊天 JSON"}
      description={action?.type === "empty" ? `将永久删除「${account.name}」回收站中的全部会话，无法还原。` : action?.type === "move"
        ? "选择目标账号。复制后保留来源会话，目标中已有的会话会跳过。" : "将 Claude 导出的聊天保存到所选账号的本地会话列表。"}
      footer={<><Button variant="ghost" disabled={busy} onClick={() => setAction(null)}>取消</Button>
        <Button variant={action?.type === "empty" ? "destructive" : "default"} disabled={busy || (action?.type !== "empty" && !target) || (action?.type === "import" && !file)}
          onClick={() => needsRestart ? setConfirmRestart(true) : submit()}>
          {busy ? "处理中…" : action?.type === "empty" ? "永久删除" : action?.type === "move" ? "迁移" : "导入"}</Button></>}>
      {action && action.type !== "empty" && <div className="space-y-3">
        <AccountPicker label="目标账号" profiles={profiles} disabled={busy} value={target} onChange={setTarget} exclude={action.type === "move" ? account.id : undefined} />
        {action.type === "move" && profiles.length < 2 && <p className="text-sm text-muted">请先添加另一个账号。</p>}
        {action.type === "import" && <p className="break-all text-sm text-muted">已选择：{file?.name}</p>}
      </div>}
    </Dialog>
    <Dialog open={confirmRestart && !!action} onClose={() => { if (!busy) setConfirmRestart(false); }}
      title={`需要重启「${targetProfile?.name ?? ""}」`}
      description={`迁移成功后需要重启「${targetProfile?.name ?? ""}」账号，迁移的会话才会显示。重启会关闭该账号当前的窗口和正在运行的任务。`}
      footer={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmRestart(false)}>取消</Button>
        <Button disabled={busy} onClick={() => submit(true)}>{busy ? "处理中…" : "立即重启"}</Button></>} />
    <Dialog open={!!chat} title={chat?.title ?? ""} onClose={() => setChat(null)}
      footer={<Button disabled={busy} onClick={() => run(async () => {
        if (!chat) return;
        const path = await api.saveTranscript([chat.title, ...chat.turns].join("\n\n"));
        await api.launch(account.id); await api.revealTranscript(path);
        toast("将文本附件添加到 Claude 新聊天即可续聊。");
      })}>在此账号续聊</Button>}>
      <div className="selectable whitespace-pre-wrap text-sm">{chat?.turns.join("\n\n")}</div>
    </Dialog>
  </>;
}
