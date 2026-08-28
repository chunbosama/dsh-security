import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";

export const name = "security-file-protect";
export const inject = ["security"];

export const NS = settingsNamespace("dsh-security-file-protect");

export const Config = z.object({
  enabled: z.boolean().default(true),
  intervalSeconds: z.natural().default(60),
  // explicit list of critical file paths (absolute, or relative to DSH_HOME)
  files: z.array(z.string()).default([]),
  // when true, silently re-baseline on next check (discards prior baselines)
  rescanBaseline: z.boolean().default(false),
  // path -> md5 baseline (maintained by this module)
  baselines: z.dict(z.string()).default({}),
});

function md5(buffer) {
  return createHash("md5").update(buffer).digest("hex");
}

/** Default critical files under DSH_HOME, when none are configured. */
function defaultFiles(dshHome) {
  return [
    path.join(dshHome, "cordis.patch.yml"),
    path.join(dshHome, "profiles", "web", "cordis.patch.yml"),
    path.join(dshHome, "profiles", "web", "cordis.yml"),
    path.join(dshHome, "settings.yaml"),
    path.join(dshHome, ".credentials.yaml"),
  ];
}

async function fileMd5(filePath) {
  const data = await readFile(filePath);
  return md5(data);
}

function apply(ctx, config = {}) {
  const sec = ctx.get("security");
  if (!sec) {
    ctx.logger?.warn?.("[dsh-security.file-protect] core not mounted; module idle");
    return;
  }
  const dshHome = process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
  const scoped = {};

  ctx.inject(["settings", "timer"], (tctx) => {
    const scope = tctx.settings.register(NS, Config, { base: config });
    scoped.get = () => scope.get() ?? config;

    const unregister = sec.registerModule({
      id: "file-protect",
      name: "关键文件保护",
      description: "定时检测 dsh 关键文件的 MD5，并在文件被修改时发出告警。",
      version: "0.1.0",
      category: "file",
      enabled: scoped.get().enabled !== false,
    });

    const runCheck = async () => {
      let cfg = scoped.get();
      if (cfg.enabled === false) return;
      let files = (cfg.files && cfg.files.length ? cfg.files : defaultFiles(dshHome)).map((f) =>
        path.isAbsolute(f) ? f : path.join(dshHome, f));
      let baselines = cfg.baselines ?? {};
      if (cfg.rescanBaseline) {
        baselines = {};
        await scope.update({ rescanBaseline: false }).catch(() => {});
      }
      for (const file of files) {
        let current;
        try {
          current = await fileMd5(file);
        } catch {
          // 文件不存在：不算修改事件
          continue;
        }
        const prev = baselines[file];
        if (prev === undefined) {
          baselines[file] = current; // establish baseline on first observation
          continue;
        }
        if (prev !== current) {
          // Do NOT auto-update the baseline: keep flagging until an admin re-baselines.
          ctx.logger?.warn?.(`[dsh-security.file-protect] 关键文件被修改: ${file} (${prev} -> ${current})`);
          await sec.alert({
            type: "critical-file-modified",
            path: file,
            details: `MD5 发生变化：${prev} -> ${current}。若此为正常变更，请将模块设置中的 rescanBaseline 置为 true 以重新建立基线。`,
            time: new Date().toISOString(),
          }).catch(() => {});
        }
      }
      await scope.update({ baselines }).catch(() => {});
    };

    tctx.interval(runCheck, (cfg.intervalSeconds ?? 60) * 1000);
    tctx.effect(() => () => unregister(), "dsh-security.file-protect teardown");

    // run once shortly after boot so the baseline is established quickly
    tctx.timeout(runCheck, 3000);
  });
}

export { apply };
