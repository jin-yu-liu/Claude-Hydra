import { parseDocument } from "yaml";
import type { NodeConfig } from "./api";
import { MAX_FRONT, emptyNode } from "./node";

/** Mihomo proxy entry, as in a Clash `proxies:` list. */
type Proxy = Record<string, unknown> & { name: string; type: string; server: string; port: number };

const usable = (p: any): p is Proxy => {
  if (!p || typeof p !== "object" || typeof p.server !== "string" || !p.server || typeof p.name !== "string" || typeof p.type !== "string") return false;
  const port = Number(p.port);
  return Number.isInteger(port) && port > 0 && port <= 65535;
};

/**
 * Turns Clash proxy entries into nodes. A node with `dialer-proxy` is reached through another
 * entry of the same list, which is saved with it as its front proxy; proxy groups and loops
 * cannot be saved and are counted as skipped.
 */
function toNodes(rows: unknown[]): { items: NodeConfig[]; skipped: number } {
  const byName = new Map<string, Proxy>(rows.filter(usable).map((p) => [p.name, p]));
  const build = (p: Proxy, seen: string[]): NodeConfig | null => {
    const node: NodeConfig = { ...emptyNode(), kind: "clash", host: p.server, port: Number(p.port), password: JSON.stringify(p) };
    const front = p["dialer-proxy"];
    if (front == null || front === "") return node;
    const next = typeof front === "string" ? byName.get(front) : undefined;
    if (!next || seen.includes(front as string) || seen.length >= MAX_FRONT) return null;
    const via = build(next, [...seen, front as string]);
    return via && { ...node, via };
  };
  let skipped = 0;
  const items = rows.filter(usable).flatMap((p) => {
    const node = build(p, [p.name]);
    if (!node) skipped++;
    return node ? [node] : [];
  });
  return { items, skipped };
}

function parseYaml(raw: string): unknown {
  if (raw.length > 4194304) throw new Error("配置超过 4 MB。");
  const doc = parseDocument(raw);
  if (doc.errors.length) throw new Error("无法解析 YAML。");
  return doc.toJS({ maxAliasCount: 50 });
}

/** Nodes of a Clash subscription (a YAML document with a `proxies:` list). */
export function subscriptionNodes(raw: string): { items: NodeConfig[]; skipped: number } {
  let data: unknown;
  try { data = parseYaml(raw); } catch { throw new Error("无法解析 YAML，请确认订阅地址返回 Clash 格式配置。"); }
  const rows = (data as any)?.proxies;
  if (!Array.isArray(rows)) throw new Error("配置中没有 proxies 节点列表。");
  return toNodes(rows);
}

// ---------------------------------------------------------------------------------------------
// Pasted nodes: share links (one per line, or a base64 list of them) or Clash YAML.

/** Base64 / base64url to UTF-8 text; null when it is not valid base64. */
function unbase64(text: string): string | null {
  const s = text.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!s || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s.padEnd(Math.ceil(s.length / 4) * 4, "="));
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch { return null; }
}

const decode = (s: string) => { try { return decodeURIComponent(s); } catch { return s; } };
const truthy = (v: string | null) => v === "1" || v?.toLowerCase() === "true";
const list = (v: string | null) => (v ? v.split(",").map((x) => x.trim()).filter(Boolean) : undefined);

/** host and port from `host:port` / `[v6]:port`. */
function hostPort(text: string): { server: string; port: number } | null {
  const m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(text) ?? /^([^:\[\]]+):(\d{1,5})$/.exec(text);
  return m ? { server: m[1], port: Number(m[2]) } : null;
}

/** Splits `scheme://userinfo@host:port/path?query#name` without URL's special-scheme rules. */
function split(link: string) {
  const scheme = /^([a-z0-9+.-]+):\/\//i.exec(link)![1].toLowerCase();
  let rest = link.slice(scheme.length + 3);
  let name = "";
  const hash = rest.indexOf("#");
  if (hash >= 0) { name = decode(rest.slice(hash + 1)).trim(); rest = rest.slice(0, hash); }
  let query = new URLSearchParams();
  const q = rest.indexOf("?");
  if (q >= 0) { query = new URLSearchParams(rest.slice(q + 1)); rest = rest.slice(0, q); }
  const at = rest.lastIndexOf("@");
  const userinfo = at >= 0 ? rest.slice(0, at) : "";
  const address = (at >= 0 ? rest.slice(at + 1) : rest).replace(/\/+$/, "");
  return { scheme, name, query, userinfo, address };
}

/** `type` / `network` transport options shared by VLESS, VMess and Trojan links. */
function transport(p: Record<string, unknown>, network: string, o: { path?: string; host?: string; serviceName?: string }) {
  const net = network === "httpupgrade" ? "ws" : network;
  if (!net || net === "tcp" || net === "none") return;
  p.network = net;
  if (net === "ws") {
    p["ws-opts"] = { path: o.path || "/", ...(o.host ? { headers: { Host: o.host } } : {}) };
    if (network === "httpupgrade") (p["ws-opts"] as any)["v2ray-http-upgrade"] = true;
  } else if (net === "grpc") {
    p["grpc-opts"] = { "grpc-service-name": o.serviceName || o.path || "" };
  } else if (net === "h2") {
    p["h2-opts"] = { path: o.path || "/", ...(o.host ? { host: list(o.host) } : {}) };
  } else if (net === "http") {
    p["http-opts"] = { path: [o.path || "/"], ...(o.host ? { headers: { Host: list(o.host) } } : {}) };
  }
}

/** TLS fields common to most link formats. */
function tls(p: Record<string, unknown>, q: URLSearchParams, sniKey: "servername" | "sni") {
  const sni = q.get("sni") || q.get("peer") || q.get("servername");
  if (sni) p[sniKey] = sni;
  const alpn = list(q.get("alpn"));
  if (alpn) p.alpn = alpn;
  if (q.get("fp")) p["client-fingerprint"] = q.get("fp");
  if (truthy(q.get("allowInsecure")) || truthy(q.get("insecure")) || truthy(q.get("allow_insecure"))) p["skip-cert-verify"] = true;
}

function shadowsocks(link: string): Proxy {
  const { name, query, userinfo, address } = split(link);
  let method: string, password: string, at: { server: string; port: number } | null;
  if (userinfo) {
    // SIP002: base64(method:password)@host:port, or the plain form used by 2022 ciphers.
    const plain = decode(userinfo);
    const cred = plain.includes(":") ? plain : unbase64(userinfo) ?? "";
    const i = cred.indexOf(":");
    method = cred.slice(0, i); password = cred.slice(i + 1);
    at = hostPort(address);
  } else {
    // Legacy: base64(method:password@host:port).
    const whole = unbase64(address) ?? "";
    const j = whole.lastIndexOf("@");
    const cred = whole.slice(0, j);
    const i = cred.indexOf(":");
    method = cred.slice(0, i); password = cred.slice(i + 1);
    at = hostPort(whole.slice(j + 1));
  }
  if (!method || !at) throw new Error("Shadowsocks 链接格式无法识别。");
  const p: Proxy = { name, type: "ss", server: at.server, port: at.port, cipher: method, password, udp: true };
  const plugin = query.get("plugin");
  if (plugin) {
    const [kind, ...opts] = decode(plugin).split(";");
    const kv = Object.fromEntries(opts.map((o) => { const k = o.indexOf("="); return k < 0 ? [o, "true"] : [o.slice(0, k), o.slice(k + 1)]; }));
    if (/obfs/.test(kind)) {
      p.plugin = "obfs";
      p["plugin-opts"] = { mode: kv.obfs || "http", ...(kv["obfs-host"] ? { host: kv["obfs-host"] } : {}) };
    } else if (/v2ray-plugin/.test(kind)) {
      p.plugin = "v2ray-plugin";
      p["plugin-opts"] = { mode: kv.mode || "websocket", tls: "tls" in kv, ...(kv.host ? { host: kv.host } : {}), ...(kv.path ? { path: kv.path } : {}), ...(kv.mux ? { mux: true } : {}) };
    } else {
      throw new Error(`不支持 Shadowsocks 插件 ${kind}。`);
    }
  }
  return p;
}

function vmess(link: string): Proxy {
  const body = link.slice("vmess://".length).split("#")[0];
  const json = unbase64(body);
  let v: any;
  try { v = JSON.parse(json ?? ""); } catch { throw new Error("VMess 链接格式无法识别（需为 v2rayN 的 base64 JSON 格式）。"); }
  const port = Number(v.port);
  const p: Proxy = {
    name: String(v.ps ?? "").trim(), type: "vmess", server: String(v.add ?? ""), port, uuid: String(v.id ?? ""),
    alterId: Number(v.aid) || 0, cipher: v.scy || "auto", udp: true,
  };
  if (v.tls === "tls") {
    p.tls = true;
    if (v.sni) p.servername = v.sni;
    if (v.alpn) p.alpn = list(String(v.alpn));
    if (v.fp) p["client-fingerprint"] = v.fp;
    if (truthy(String(v.allowInsecure ?? v.insecure ?? ""))) p["skip-cert-verify"] = true;
  }
  const net = String(v.net || "tcp");
  if (net === "tcp" && v.type === "http") {
    p.network = "http";
    p["http-opts"] = { path: [v.path || "/"], ...(v.host ? { headers: { Host: list(v.host) } } : {}) };
  } else {
    transport(p, net, { path: v.path, host: v.host, serviceName: v.path });
  }
  return p;
}

function vless(link: string): Proxy {
  const { name, query: q, userinfo, address } = split(link);
  const at = hostPort(address);
  if (!at || !userinfo) throw new Error("VLESS 链接格式无法识别。");
  const p: Proxy = { name, type: "vless", server: at.server, port: at.port, uuid: decode(userinfo), udp: true };
  const security = q.get("security") || "none";
  if (security === "tls" || security === "reality" || security === "xtls") {
    p.tls = true;
    tls(p, q, "servername");
  }
  if (security === "reality") {
    p["reality-opts"] = { "public-key": q.get("pbk") || "", ...(q.get("sid") ? { "short-id": q.get("sid") } : {}) };
    if (!p["client-fingerprint"]) p["client-fingerprint"] = "chrome";
  }
  if (q.get("flow")) p.flow = q.get("flow");
  transport(p, q.get("type") || "tcp", { path: q.get("path") ?? undefined, host: q.get("host") ?? undefined, serviceName: q.get("serviceName") ?? undefined });
  return p;
}

function trojan(link: string): Proxy {
  const { name, query: q, userinfo, address } = split(link);
  const at = hostPort(address);
  if (!at || !userinfo) throw new Error("Trojan 链接格式无法识别。");
  const p: Proxy = { name, type: "trojan", server: at.server, port: at.port, password: decode(userinfo), udp: true };
  tls(p, q, "sni");
  transport(p, q.get("type") || "tcp", { path: q.get("path") ?? undefined, host: q.get("host") ?? undefined, serviceName: q.get("serviceName") ?? undefined });
  return p;
}

function hysteria2(link: string): Proxy {
  const { name, query: q, userinfo, address } = split(link);
  // Port hopping puts a range after the host (`host:443,5000-6000`); the first port is the main one.
  const m = /^(\[[^\]]+\]|[^:]+):(\d{1,5})(?:[,-][\d,-]*)?$/.exec(address);
  if (!m) throw new Error("Hysteria2 链接格式无法识别。");
  const p: Proxy = { name, type: "hysteria2", server: m[1].replace(/^\[|\]$/g, ""), port: Number(m[2]), password: decode(userinfo) };
  const hop = address.slice(m[1].length + 1);
  if (/[,-]/.test(hop)) p.ports = hop;
  if (q.get("mport")) p.ports = q.get("mport");
  tls(p, q, "sni");
  if (q.get("obfs")) { p.obfs = q.get("obfs"); p["obfs-password"] = q.get("obfs-password") || ""; }
  return p;
}

function tuic(link: string): Proxy {
  const { name, query: q, userinfo, address } = split(link);
  const at = hostPort(address);
  const i = userinfo.indexOf(":");
  if (!at || i < 0) throw new Error("TUIC 链接格式无法识别。");
  const p: Proxy = { name, type: "tuic", server: at.server, port: at.port, uuid: decode(userinfo.slice(0, i)), password: decode(userinfo.slice(i + 1)) };
  tls(p, q, "sni");
  if (q.get("congestion_control")) p["congestion-controller"] = q.get("congestion_control");
  if (q.get("udp_relay_mode")) p["udp-relay-mode"] = q.get("udp_relay_mode");
  return p;
}

function socksOrHttp(link: string): Proxy {
  const { scheme, name, userinfo, address } = split(link);
  const at = hostPort(address);
  if (!at) throw new Error("代理链接格式无法识别。");
  const p: Proxy = { name, type: scheme.startsWith("socks") ? "socks5" : "http", server: at.server, port: at.port };
  if (scheme === "https") p.tls = true;
  if (userinfo) {
    const i = userinfo.indexOf(":");
    p.username = decode(i < 0 ? userinfo : userinfo.slice(0, i));
    if (i >= 0) p.password = decode(userinfo.slice(i + 1));
  }
  return p;
}

const PARSERS: Record<string, (link: string) => Proxy> = {
  ss: shadowsocks, vmess, vless, trojan, hysteria2, hy2: hysteria2, tuic,
  socks: socksOrHttp, socks5: socksOrHttp, socks5h: socksOrHttp, http: socksOrHttp, https: socksOrHttp,
};

/** Link schemes the paste box understands, for hints and errors. */
export const LINK_SCHEMES = "ss、vmess、vless、trojan、hysteria2 / hy2、tuic、socks5、http(s)";

/** One share link as a Clash proxy entry. Errors are user-facing. */
export function linkProxy(link: string): Proxy {
  const scheme = /^([a-z0-9+.-]+):\/\//i.exec(link.trim())?.[1].toLowerCase();
  const parse = scheme ? PARSERS[scheme] : undefined;
  if (!parse) throw new Error(scheme ? `不支持 ${scheme}:// 链接。支持：${LINK_SCHEMES}。` : "无法识别的节点链接。");
  const p = parse(link.trim());
  if (!usable({ ...p, name: p.name || "x" })) throw new Error(`${scheme}:// 链接缺少服务器或端口。`);
  if (!p.name) p.name = `${p.type} ${p.server.includes(":") ? `[${p.server}]` : p.server}:${p.port}`;
  return p;
}

/**
 * Nodes from pasted text: share links (one per line, or a base64 block of them, as many
 * subscriptions serve), a single Clash proxy entry in YAML, a YAML list of entries, or a
 * whole Clash config with `proxies:`. Errors are user-facing.
 */
export function pastedNodes(text: string): { items: NodeConfig[]; skipped: number } {
  const raw = text.trim();
  if (!raw) throw new Error("请粘贴节点链接或 Clash 节点配置。");
  const linkLine = /^[a-z0-9+.-]+:\/\/\S+$/i;
  const asLinks = (t: string) => {
    const lines = t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    return lines.length && lines.every((l) => linkLine.test(l)) ? lines : null;
  };
  const links = asLinks(raw) ?? (() => { const d = unbase64(raw); return d ? asLinks(d) : null; })();
  if (links) {
    // A first bad link is reported as is; with several, the bad ones are only counted.
    if (links.length === 1) return toNodes([linkProxy(links[0])]);
    const proxies = links.flatMap((l) => { try { return [linkProxy(l)]; } catch { return []; } });
    if (!proxies.length) linkProxy(links[0]);
    const out = toNodes(proxies);
    return { items: out.items, skipped: out.skipped + links.length - proxies.length };
  }
  let data: unknown;
  try { data = parseYaml(raw); } catch {
    throw new Error(`无法识别。请粘贴节点链接（${LINK_SCHEMES}）或 Clash 节点 YAML。`);
  }
  const rows = Array.isArray(data) ? data
    : Array.isArray((data as any)?.proxies) ? (data as any).proxies
    : data && typeof data === "object" ? [{ name: "", ...(data as object) }]
    : null;
  if (!rows) throw new Error(`无法识别。请粘贴节点链接（${LINK_SCHEMES}）或 Clash 节点 YAML。`);
  // A pasted single entry may leave out its name.
  const named = rows.map((p: any) => (p && typeof p === "object" && !p.name && typeof p.server === "string") ? { ...p, name: `${p.type} ${p.server}:${p.port}` } : p);
  const out = toNodes(named);
  if (!out.items.length) throw new Error(out.skipped ? "这些节点依赖代理组或缺失的前置节点（dialer-proxy），无法单独使用。" : "没有找到可用的节点：需要 type、server 与 port。");
  return out;
}
