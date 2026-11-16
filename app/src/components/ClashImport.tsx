import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { MAX_FRONT, fronts, hopLabel } from "@/lib/node";
import { LINK_SCHEMES, pastedNodes, subscriptionNodes } from "@/lib/clashNodes";
import { errorText, type ClashSubscription, type NodeConfig } from "@/lib/api";
import { Button } from "./ui/button";
import { Input, Select, Textarea } from "./ui/input";

const skippedNote = (n: number) => `已略过 ${n} 个节点：链接无法识别，或前置节点（dialer-proxy）是代理组、不存在、成环或超过 ${MAX_FRONT} 级。`;

export function ClashImport({ subscription, onSubscriptionChange, node, choose }: { subscription?: ClashSubscription | null; onSubscriptionChange: (s: ClashSubscription) => void; node: NodeConfig | null; choose: (n: NodeConfig) => void }) {
  const [url, setUrl] = useState<string | null>(null);
  const address = url ?? subscription?.url ?? "";
  const list = subscription?.nodes ?? [];
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  // Pasting a node (share link or Clash YAML) instead of reading a subscription. Pasted nodes
  // are only offered here; the saved subscription stays as it was.
  const [pasting, setPasting] = useState(false);
  const [text, setText] = useState("");
  const [pasted, setPasted] = useState<NodeConfig[]>([]);
  async function load(source: Promise<string>) {
    setBusy(true); setError(""); setNote("");
    try {
      const { items, skipped } = subscriptionNodes(await source);
      if (!items.length) throw new Error(skipped ? "订阅中的节点都依赖代理组或缺失的前置节点，无法单独使用。" : "没有可选择的节点。");
      if (skipped) setNote(skippedNote(skipped));
      onSubscriptionChange({ url: address.trim(), nodes: items });
      setUrl(null);
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  }
  function importPasted() {
    setError(""); setNote("");
    try {
      const { items, skipped } = pastedNodes(text);
      if (skipped) setNote(skippedNote(skipped));
      if (items.length === 1) { choose(items[0]); setPasted([]); setText(""); setPasting(false); }
      else setPasted(items);
    } catch (e) { setError(errorText(e)); }
  }
  const name = (n: NodeConfig) => hopLabel(n);
  const chain = (n: NodeConfig) => fronts(n).map((v) => ` ← ${hopLabel(v)}`).join("");
  const same = (a: NodeConfig, b: NodeConfig | null) => !!b && a.password === b.password && JSON.stringify(a.via ?? null) === JSON.stringify(b.via ?? null);
  const picker = (nodes: NodeConfig[], label: string) => <Select disabled={busy} aria-label={label} value={Math.max(nodes.findIndex(n => same(n, node)), nodes.findIndex(n => n.password === node?.password))} onChange={e => { const n=nodes[Number(e.target.value)]; if(n) choose(n); }}>
    <option disabled value={-1}>选择节点（{nodes.length}）</option>
    {nodes.map((n,i) => <option key={i} value={i}>{name(n)} · {JSON.parse(n.password).type}{n.via ? `（经 ${hopLabel(n.via)} 中转）` : ""}</option>)}
  </Select>;
  return <div className="space-y-2 px-4 py-2">
    <div className="flex items-center gap-2">
      <Input aria-label="Clash 订阅地址" type="password" placeholder="Clash 订阅地址" value={address} disabled={busy} onChange={e => setUrl(e.target.value)} />
      <Button variant="outline" disabled={busy || !address.trim()} onClick={() => load(invoke<string>("clash_subscription", { url: address }))}>{busy ? "读取中…" : "读取订阅"}</Button>
      <Button variant={pasting ? "outline" : "ghost"} disabled={busy} aria-expanded={pasting} onClick={() => { setPasting(!pasting); setError(""); setNote(""); }}>粘贴节点</Button>
    </div>
    {pasting && <div className="space-y-2">
      <Textarea aria-label="节点链接或 Clash 节点配置" rows={4} spellCheck={false} className="font-mono text-xs"
        placeholder={"粘贴节点分享链接（每行一个），或单个 Clash 节点的 YAML，例如：\nvless://uuid@1.2.3.4:443?security=reality&pbk=…#我的 VPS\n\n- {name: 我的 VPS, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: …}"}
        value={text} onChange={e => setText(e.target.value)} />
      <div className="flex items-center gap-2">
        <Button variant="outline" disabled={!text.trim()} onClick={importPasted}>导入节点</Button>
        <p className="text-xs text-muted">支持 {LINK_SCHEMES}。节点只保存在此环境中，不会改动已读取的订阅。</p>
      </div>
      {pasted.length > 1 && picker(pasted, "选择粘贴的节点")}
    </div>}
    {!list.length && node?.kind === "clash" && !pasting && <p className="text-xs text-muted">此环境只保存了绑定节点。读取订阅或粘贴节点即可切换。</p>}
    {!!list.length && picker(list, "选择 Clash 节点")}
    {node?.kind === "clash" && <p className="text-xs">已绑定：{name(node)} · {node.host}:{node.port}{chain(node)}</p>}
    {node?.kind === "clash" && <p className="text-xs text-muted">保存环境后，在“账号 → 编辑”中绑定此环境。</p>}
    {note && <p className="text-xs text-muted">{note}</p>}
    {error && <p role="alert" className="text-xs text-danger">{error}</p>}
  </div>;
}
