import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";

const scryptAsync = promisify(scrypt);

export const name = "security-core";

/** Settings namespace owned by the security core. */
export const NS = settingsNamespace("dsh-security");

export const Config = z.object({
  adminPasswordHash: z.string().role("secret").optional(),
  // set by the control-panel client (plaintext, write-only); core hashes it into adminPasswordHash
  adminPasswordPending: z.string().role("secret").optional(),
  trustedIps: z.array(z.string()).default([]),
  modules: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string().optional(),
    version: z.string().optional(),
    category: z.string().optional(),
    enabled: z.boolean().default(true),
  })).default([]),
  seenIps: z.dict(z.object({
    count: z.number().default(0),
    last: z.number().default(0),
  })).default({}),
});

export const DEFAULT_THRESHOLD = 3;

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  return scryptAsync(password, salt, 32).then((derived) =>
    `${salt}:${derived.toString("hex")}`);
}

async function verifyPassword(password, stored) {
  if (!stored || typeof password !== "string" || password.length === 0) return false;
  const sep = stored.indexOf(":");
  if (sep === -1) return false;
  const salt = stored.slice(0, sep);
  const hashHex = stored.slice(sep + 1);
  if (!salt || !/^[0-9a-f]+$/i.test(hashHex)) return false;
  let expected;
  try {
    expected = Buffer.from(hashHex, "hex");
  } catch {
    return false;
  }
  const derived = await scryptAsync(password, salt, expected.length);
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

function apply(ctx, config = {}) {
  const core = {
    config: {
      commonThreshold: config.commonThreshold ?? DEFAULT_THRESHOLD,
      ipRetentionMs: config.ipRetentionMs ?? 7 * 24 * 3600 * 1000,
      unlockTtlMs: config.unlockTtlMs ?? 30 * 60 * 1000,
    },
    trustedIps: [...(config.trustedIps ?? [])],
    modules: new Map(),
    scope: null,
    persistTimer: null,
  };

  const memory = {
    adminPasswordHash: config.adminPasswordHash,
    trustedIps: [...core.trustedIps],
    modules: [...(config.modules ?? [])],
    seenIps: {},
  };

  core.state = {
    get: () => memory,
    async update(patch) {
      Object.assign(memory, patch);
      if (core.scope) await core.scope.update(patch).catch(() => {});
    },
    async mutate(ops) {
      if (core.scope) await core.scope.mutate(ops).catch(() => {});
    },
  };

  const ip = createIpTracker(core);

  function syncRoster(moduleList) {
    const byId = new Map(moduleList.map((m) => [m.id, m]));
    for (const [id, live] of core.modules) byId.set(id, live);
    memory.modules = [...byId.values()];
  }

  core.getTrustedIps = () => core.trustedIps;
  core.persistIpsDebounced = () => {
    if (!core.scope) return;
    if (core.persistTimer) return;
    core.persistTimer = setTimeout(() => {
      core.persistTimer = null;
      core.state.update({ seenIps: ip.snapshot() }).catch(() => {});
    }, 2000);
  };

  // Optional settings wiring — the suite also works without a settings provider.
  ctx.inject(["settings"], (sctx) => {
    core.scope = sctx.settings.register(NS, Config, { base: config });
    const resolved = core.scope.get() ?? {};
    if (resolved.adminPasswordHash) memory.adminPasswordHash = resolved.adminPasswordHash;
    if (Array.isArray(resolved.trustedIps)) { core.trustedIps = [...resolved.trustedIps]; memory.trustedIps = [...resolved.trustedIps]; }
    if (Array.isArray(resolved.modules)) syncRoster(resolved.modules);
    if (resolved.seenIps) { memory.seenIps = resolved.seenIps; ip.load(resolved.seenIps); }
    core.scope.watch((next) => {
      if (!next) return;
      if (Array.isArray(next.trustedIps)) core.trustedIps = [...next.trustedIps];
      if (Array.isArray(next.modules)) syncRoster(next.modules);
      // hash any pending plaintext password supplied by the control panel
      if (typeof next.adminPasswordPending === "string" && next.adminPasswordPending.length > 0) {
        const pending = next.adminPasswordPending;
        core.password.set(pending)
          .then(() => core.scope.mutate([{ op: "unset", path: ["adminPasswordPending"] }]).catch(() => {}))
          .catch((e) => ctx.logger?.warn?.("[dsh-security] failed to hash admin password: " + String(e)));
      }
    });
  });

  // Module registry (in-memory roster, persisted to settings).
  core.registerModule = (desc) => {
    const id = desc.id;
    core.modules.set(id, { ...core.modules.get(id), ...desc });
    memory.modules = [...core.modules.values()];
    core.state.update({ modules: memory.modules }).catch(() => {});
    return () => {
      core.modules.delete(id);
      memory.modules = [...core.modules.values()];
      core.state.update({ modules: memory.modules }).catch(() => {});
    };
  };
  core.listModules = () => [...core.modules.values()];
  core.getModule = (id) => core.modules.get(id);

  core.password = {
    isSet: () => Boolean(memory.adminPasswordHash),
    async set(password) {
      const hash = await hashPassword(password);
      memory.adminPasswordHash = hash;
      await core.state.update({ adminPasswordHash: hash });
      return true;
    },
    async verify(password) {
      return verifyPassword(password, memory.adminPasswordHash);
    },
    async clear() {
      memory.adminPasswordHash = undefined;
      await core.state.mutate([{ op: "unset", path: ["adminPasswordHash"] }]);
    },
  };

  const unlockUntil = { at: 0 };
  core.securitySession = {
    unlock() { unlockUntil.at = Date.now() + core.config.unlockTtlMs; },
    lock() { unlockUntil.at = 0; },
    isUnlocked() { return Date.now() < unlockUntil.at; },
  };

  core.ip = {
    record: (address) => ip.record(address),
    isTrusted: (address) => ip.isTrusted(address),
    verdict: (address) => ip.verdict(address),
    markTrusted(address) {
      if (!core.trustedIps.includes(address)) {
        core.trustedIps.push(address);
        core.state.update({ trustedIps: [...core.trustedIps] }).catch(() => {});
      }
    },
    unmarkTrusted(address) {
      core.trustedIps = core.trustedIps.filter((x) => x !== address);
      core.state.update({ trustedIps: [...core.trustedIps] }).catch(() => {});
    },
  };

  core.alert = async (payload) => {
    let dispatched = false;
    for (const module of core.modules.values()) {
      if (module.enabled !== false && module.handleAlert && !module.alertBusy) {
        dispatched = true;
        module.alertBusy = true;
        try {
          await module.handleAlert(payload);
        } catch (error) {
          ctx.logger?.warn?.(`[dsh-security] alert handler of ${module.id} failed: ${String(error)}`);
        } finally {
          module.alertBusy = false;
        }
      }
    }
    if (!dispatched) {
      ctx.logger?.warn?.("[dsh-security] protection triggered but no attack-alert module is installed", payload?.type);
    }
    return dispatched;
  };

  ctx.provide("security", {
    registerModule: core.registerModule,
    listModules: core.listModules,
    getModule: core.getModule,
    password: core.password,
    ip: core.ip,
    alert: core.alert,
    securitySession: core.securitySession,
    threshold: core.config.commonThreshold,
  });

  ctx.effect(() => () => {
    if (core.persistTimer) clearTimeout(core.persistTimer);
    core.modules.clear();
  }, "dsh-security: core teardown");
}

function createIpTracker(core) {
  const seen = new Map();
  return {
    load(snapshot) {
      seen.clear();
      for (const [address, rec] of Object.entries(snapshot ?? {})) {
        if (rec && typeof rec.count === "number") {
          seen.set(address, { count: rec.count, first: rec.last ?? rec.first, last: rec.last });
        }
      }
    },
    record(address) {
      if (!address) return;
      const now = Date.now();
      const rec = seen.get(address) ?? { count: 0, first: now, last: now };
      rec.count += 1;
      rec.last = now;
      seen.set(address, rec);
      core.persistIpsDebounced();
    },
    isTrusted(address) {
      return core.getTrustedIps().includes(address);
    },
    count(address) {
      return seen.get(address)?.count ?? 0;
    },
    verdict(address) {
      if (core.getTrustedIps().includes(address)) return "trusted";
      return (seen.get(address)?.count ?? 0) >= core.config.commonThreshold ? "common" : "stranger";
    },
    snapshot() {
      const out = {};
      for (const [address, rec] of seen) {
        if (Date.now() - rec.last <= core.config.ipRetentionMs) {
          out[address] = { count: rec.count, last: rec.last };
        }
      }
      return out;
    },
  };
}

export { apply };
