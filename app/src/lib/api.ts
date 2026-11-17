import { invoke } from "@tauri-apps/api/core";

export interface Profile {
  badge: string;
  id: string;
  name: string;
  path: string;
  isDefault: boolean;
  pid: number | null;
  lastUsed: number | null;
  color: number;
  keepRunning: boolean;
  signedIn: boolean | null;
  /** Name of the assigned environment config. */
  environment: string | null;
  /** Why the exit guard cut this account's network, while it is cut. */
  blocked: string | null;
  /** The cut is temporary: checks kept failing and Hydra keeps re-checking by itself. */
  blockedSoft: boolean;
}

export interface ProfileOptions {
  name: string;
  color: number;
  keepRunning: boolean;
  /** Assigned environment id; "" = none. */
  environment: string;
  lastExit: ExitInfo | null;
}

export interface ClashSubscription { url: string; nodes: NodeConfig[] }

export interface EnvironmentInput {
  clashSubscription?: ClashSubscription | null;
  name: string;
  node: NodeConfig | null;
  /** "proxy" | "system" | IANA name */
  timezone: string;
  locale: string;
  args: string;
  /** One NAME=value per line. */
  env: string;
  /** Last successful connectivity check of the node. */
  lastCheck: NodeCheck | null;
  /** "" | "static" | "city" | "region" | "country" */
  exitRule: ExitRule;
  /** Allow mainland-China exits (blocked by default). */
  allowCn: boolean;
  /** "" | "sandboxie" */
  isolation: "" | "sandboxie";
  /** Each account gets its own Claude Code login and configuration directory. */
  separateCode: boolean;
}
export type ExitRule = "" | "static" | "city" | "region" | "country";
export interface Environment extends EnvironmentInput {
  id: string;
  usedBy: string[];
  /** Exit timezone last confirmed for the node (connectivity or launch check). */
  detectedTimezone: string | null;
  /** Exit the rule is bound to (set by the first verified check). */
  exitBaseline: ExitInfo | null;
}

export type NodeKind = "clash" | "http" | "https" | "socks5";
export interface NodeConfig {
  kind: NodeKind; host: string; port: number; username: string; password: string;
  ipVersion: "ipv4" | "ipv6"; geoChannel: "ipinfo" | "ipapi" | "ip-api"; refreshUrl: string;
  /** Front (transit) proxy this node is reached through; may itself have one. */
  via?: NodeConfig | null;
}
export interface NodeCheck { exit: ExitInfo; quality: string | null; risk: string }
/** A published release and its markdown notes. */
export interface ReleaseNote { version: string; date: string; body: string }
export interface ExitInfo { ip: string; country: string; region: string; city: string; timezone: string; checkedAt: number }

export interface Install {
  kind: string;
  exe: string | null;
  version: string | null;
  family: string | null;
  aumid: string | null;
  defaultProfile: string;
}

export interface AppInfo {
  version: string;
  platform: string;
  install: Install | null;
  installError: string | null;
  claudePath: string | null;
  storageRoot: string;
  settingsPath: string;
  autostart: boolean;
  /** Extra accounts refuse to start without a proxy environment. */
  requireEnvironment: boolean;
}

export interface QuotaWindow { utilization: number; resetsAt: string | null }
export interface Quota { fiveHour: QuotaWindow | null; sevenDay: QuotaWindow | null; fetchedAt: number }

export interface CodeSession {
  id: string; title: string; cwd: string | null; cwdExists: boolean; lastActivityAt: number | null; model: string | null; turns: number | null; inTarget: boolean;
}
export interface SessionPreview { sessions: CodeSession[]; targetProblem: string | null; running: boolean }
export interface TransferResult { copied: number; skipped: number; failed: number; updated: number; forked: number }

export const api = {
  listProfiles: () => invoke<Profile[]>("list_profiles"),
  launch: (id: string) => invoke<string>("launch_profile", { id }),
  close: (id: string) => invoke<string>("close_profile", { id }),
  restart: (id: string) => invoke<string>("restart_profile", { id }),
  addAccount: () => invoke<Profile>("add_account"),
  nextAccountName: () => invoke<string>("next_account_name"),
  createConfiguredAccount: (name: string, environment: string) => invoke<Profile>("create_configured_account", { name, environment }),
  listEnvironments: () => invoke<Environment[]>("list_environments"),
  saveEnvironment: (id: string | null, input: EnvironmentInput) => invoke<string>("save_environment", { id, input }),
  deleteEnvironment: (id: string) => invoke<void>("delete_environment", { id }),
  options: (id: string) => invoke<ProfileOptions>("profile_options", { id }),
  saveOptions: (id: string, options: ProfileOptions) => invoke<void>("save_profile_options", { id, options }),
  remove: (id: string) => invoke<void>("delete_profile", { id }),
  openFolder: (id: string) => invoke<void>("open_profile_folder", { id }),
  createShortcut: (id: string) => invoke<string>("create_shortcut", { id }),
  setupLoginRouter: () => invoke<void>("setup_login_router"),
  prepareLogin: (id: string) => invoke<void>("prepare_login", { id }),
  openAccountBrowser: (id: string, url?: string) => invoke<void>("open_account_browser", { id, url: url ?? null }),
  resumeAccount: (id: string) => invoke<string>("resume_account", { id }),
  rebindExit: (id: string) => invoke<string>("rebind_exit", { id }),
  sandboxStatus: () => invoke<string>("sandbox_status"),
  openSandboxManager: () => invoke<void>("open_sandbox_manager"),
  diagnostics: () => invoke<string>("diagnostics"),
  saveTranscript: (text: string) => invoke<string>("save_transcript", { text }),
  revealTranscript: (path: string) => invoke<void>("reveal_transcript", { path }),
  checkNode: (node: NodeConfig) => invoke<[ExitInfo, string | null, string]>("check_node", { node }),
  refreshNodeIp: (url: string) => invoke<string>("refresh_node_ip", { url }),
  profileQuota: (id: string) => invoke<Quota>("profile_quota", { id }),
  recycleSession: (account: string, action: "delete" | "restore" | "empty", id = "") => invoke<void>("recycle_session", { account, action, id }),
  importChats: (account: string, raw: string) => invoke<TransferResult>("import_chats", { account, raw }),
  readImport: (account: string, id: string) => invoke<string>("read_import", { account, id }),
  sessionPreview: (source: string, target: string, trash = false) => invoke<SessionPreview>("session_preview", { source, target, trash }),
  copySessions: (source: string, target: string, ids: string[], restart = false) => invoke<TransferResult>("copy_sessions", { source, target, ids, restart }),
  releaseNotes: (after: string, upto: string) => invoke<ReleaseNote[]>("release_notes", { after, upto }),
  openReleasePage: (version: string) => invoke<void>("open_release_page", { version }),
  restartApp: () => invoke<void>("restart_app"),
  appInfo: () => invoke<AppInfo>("app_info"),
  setAutostart: (enabled: boolean) => invoke<void>("set_autostart", { enabled }),
  setRequireEnvironment: (enabled: boolean) => invoke<void>("set_require_environment", { enabled }),
  setClaudePath: (path: string | null) => invoke<void>("set_claude_path", { path }),
  quit: () => invoke<void>("quit_app"),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : JSON.stringify(e);
}
