import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src-tauri/", import.meta.url));
const target = process.env.TAURI_ENV_TARGET_TRIPLE || process.argv[2] ||
  /host: (\S+)/.exec(execFileSync("rustc", ["-vV"], { encoding: "utf8" }))[1];
if (!target.includes("-windows-")) process.exit(0);

const arch = { x86_64: "x64", aarch64: "ARM64" }[target.split("-")[0]];
if (!arch) throw new Error(`Sandboxie-Plus does not support ${target}`);
const release = JSON.parse(await readFile(join(root, "sandboxie-release.json"), "utf8"));
const output = join(root, "binaries", "Sandboxie-Plus-Setup.exe");
const digest = data => createHash("sha256").update(data).digest("hex");
const cached = await readFile(output).catch(error => {
  if (error.code !== "ENOENT") throw error;
});
if (cached && digest(cached) === release[arch]) process.exit(0);

const tag = `v${release.version}`;
const url = `https://github.com/sandboxie-plus/Sandboxie/releases/download/${tag}/Sandboxie-Plus-${arch}-${tag}.exe`;
console.log(`Downloading Sandboxie-Plus ${tag} (${arch})`);
const response = await fetch(url);
if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
const data = Buffer.from(await response.arrayBuffer());
if (digest(data) !== release[arch]) throw new Error("Sandboxie-Plus checksum mismatch");
await mkdir(dirname(output), { recursive: true });
const temporary = output + "." + randomUUID();
try {
  await writeFile(temporary, data);
  await rename(temporary, output);
} finally {
  await rm(temporary, { force: true });
}
