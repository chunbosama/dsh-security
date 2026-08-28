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
      name: "关键文件保护 (Critical File Protection)",
      description: "Periodically checks the MD5 of critical dsh files and alerts when a file is modified.",
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
          // file absent: not a modification event
          continue;
        }
        const prev = baselines[file];
        if (prev === undefined) {
          baselines[file] = current; // establish baseline on first observation
          continue;
        }
        if (prev !== current) {
          // Do NOT auto-update the baseline: keep flagging until an admin re-baselines.
          ctx.logger?.warn?.(`[dsh-security.file-protect] CRITICAL FILE CHANGED: ${file} (${prev} -> ${current})`);
          await sec.alert({
            type: "critical-file-modified",
            path: file,
            details: `MD5 changed: ${prev} -> ${current}. If this change was legitimate, run security_rescan_baselines or edit the module settings to re-baseline.`,
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
