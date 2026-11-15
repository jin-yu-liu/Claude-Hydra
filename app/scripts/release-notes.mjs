// Release notes for a tag, from the commits since the previous tag.
//
//   node app/scripts/release-notes.mjs v1.0.1 [previous-tag]
//
// Each commit subject becomes one item, grouped as 新功能 / 改进 / 问题修复; the "- " lines of
// its body become sub-items (a body without them is kept as one sub-item). Version bumps and
// trailers (Co-Authored-By, …) are left out. The markdown is what the in-app update dialog
// renders, and what tauri-action writes to the release and to latest.json.
//
// A release with a hand-written app/release-notes/<tag>.md uses that file as is instead, for
// releases whose headline matters more than the commit list.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const tag = process.argv[2];
if (!tag) throw new Error("usage: release-notes.mjs <tag> [previous-tag]");

const written = join(dirname(fileURLToPath(import.meta.url)), "..", "release-notes", `${tag}.md`);
if (existsSync(written)) {
  process.stdout.write(`${readFileSync(written, "utf8").trim()}\n`);
  process.exit(0);
}

let prev = process.argv[3];
if (!prev) {
  try { prev = git("describe", "--tags", "--abbrev=0", "--match", "v*", `${tag}^`); } catch { prev = ""; }
}

const SEP = "\u001e";
const log = git("log", "--no-merges", `--format=%s%x1f%b${SEP}`, prev ? `${prev}..${tag}` : tag);
const groups = { 新功能: [], 改进: [], 问题修复: [] };

for (const raw of log.split(SEP)) {
  const [subjectRaw = "", body = ""] = raw.trim().split("\u001f");
  const subject = subjectRaw.replace(/^(feat|fix|chore|refactor|perf|docs)\s*[:：]\s*/i, "").trim();
  if (!subject || /^(发布|release|bump)\s*v?\d+\.\d+\.\d+/i.test(subject)) continue;
  const lines = body.split("\n").map((l) => l.trim()).filter((l) => l && !/^[\w-]+:\s/.test(l));
  const bullets = lines.filter((l) => /^[-*]\s+/.test(l)).map((l) => l.replace(/^[-*]\s+/, ""));
  const subs = bullets.length ? bullets : lines.length ? [lines.join(" ")] : [];
  const kind = /^(新增|支持|内置|加入|增加|feat|add)/i.test(subjectRaw) ? "新功能"
    : /(修复|fix)/i.test(subject) ? "问题修复" : "改进";
  groups[kind].push([`- ${subject}`, ...subs.map((s) => `  - ${s}`)].join("\n"));
}

const out = Object.entries(groups).filter(([, items]) => items.length)
  .map(([title, items]) => `### ${title}\n\n${items.join("\n")}`).join("\n\n");
process.stdout.write(`${out || "### 改进\n\n- 常规维护与稳定性改进"}\n`);
