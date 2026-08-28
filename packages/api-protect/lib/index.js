import { randomUUID } from "node:crypto";
import z from "@deepseek-ai/schemastery";
import { toFetchHandler } from "@deepseek-ai/dsh-host-apiproxy";

export const name = "security-api-protect";
export const inject = ["security"];

export const Config = z.object({
  enabled: z.boolean().default(true),
  fakeStrangers: z.boolean().default(true),          // stranger / unauthenticated -> random data
  alertOnStranger: z.boolean().default(true),         // email the admin once per stranger IP
  trustedHosts: z.array(z.string()).default([]),      // extra LAN authorities treated as trusted
  maxRequestBodyBytes: z.natural().default(314572800),
});

// Mirror of dsh-host-apiproxy UNARY_ROUTES keys (the POST endpoints served under /api).
const API_METHODS = [
  "agentPreset.copy", "agentPreset.list", "agentPreset.openDocument", "agentPreset.read",
  "agentPreset.remove", "agentPreset.select",
  "credentials.describe", "credentials.set", "credentials.unset",
  "goal.clear", "goal.complete", "goal.create", "goal.edit", "goal.pause", "goal.resume",
  "host.createDirectory", "host.describe", "host.listDirectory", "host.openPath", "host.pickDirectory",
  "llm.discoverModels", "llm.models", "llm.providers",
  "session.attachment", "session.cancel", "session.create", "session.fork", "session.history",
  "session.list", "session.models", "session.prompt", "session.rename", "session.search",
  "session.selectModel", "session.updateQueue",
  "settings.describe", "settings.mutate", "settings.openDocument", "settings.replace", "settings.update",
  "skill.list",
  "subagent.history", "subagent.interrupt", "subagent.list", "subagent.prompt",
  "workspace.archiveSession", "workspace.create", "workspace.delete", "workspace.insertBefore",
  "workspace.insertSessionBefore", "workspace.list", "workspace.rename",
];

// Mirror of the privileged methods that dsh-client-connection pins to loopback.
const PRIVILEGED_METHODS = new Set([
  "agentPreset.read", "agentPreset.copy", "agentPreset.openDocument",
  "agentPreset.remove", "host.pickDirectory", "host.openPath",
  "settings.describe", "settings.openDocument", "settings.update",
  "settings.replace", "settings.mutate", "credentials.describe",
  "credentials.set", "credentials.unset", "llm.discoverModels",
]);

function normalizeIp(ip) {
  if (!ip) return "";
  return ip.replace(/^::ffff:/, "");
}

function isLoopback(ip) {
  return ip === "127.0.0.1" || ip === "::1" || ip === "" || ip.startsWith("127.");
}

/** DNS-rebinding / origin trust fence, mirroring dsh-client-connection. */
function isTrustedApiRequest(req, trustedHosts) {
  const hostHeader = req.headers?.host;
  let hostUrl;
  try { hostUrl = new URL(`http://${hostHeader}`); } catch { return false; }
  const hostname = hostUrl.hostname;
  const loopback = hostname === "localhost" || hostname === "[::1]" || /^127\./.test(hostname);
  if (!loopback && !trustedHosts.includes(hostname)) return false;
  if (req.headers?.["sec-fetch-site"] === "cross-site") return false;
  const origin = req.headers?.origin;
  if (origin === undefined) return true;
  try { return new URL(origin).host === hostUrl.host; } catch { return false; }
}

function randomMeaninglessValue(endpoint) {
  const pool = [
    () => ({ ok: true, value: { data: randomUUID(), nonce: Math.random().toString(36).slice(2), items: [] } }),
    () => ({ ok: true, value: { [Math.random().toString(36).slice(2, 8)]: randomUUID(), ts: Date.now() + Math.floor(Math.random() * 1e6) } }),
    () => ({ ok: true, value: { code: Math.floor(Math.random() * 1e6), status: "ok", payload: Math.random().toString(36).repeat(4) } }),
    () => ({ ok: true, value: { message: "eJyrVsosLq5WqslMLclLVyjLzE1Vss9LzPspEAA=" } }),
  ];
  return pool[Math.floor(Math.random() * pool.length)]();
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) { req.destroy(); reject(new Error("body too large")); return; }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function writeJson(res, status, obj) {
  const payload = Buffer.from(JSON.stringify(obj), "utf8");
  res.writeHead(status, { "content-type": "application/json", "content-length": payload.length });
  res.end(payload);
}

async function fakeResponse(req, res) {
  let rpcId = null;
  try {
    const body = await readBody(req, 314572800);
    const parsed = JSON.parse(body.toString("utf8"));
    if (parsed && typeof parsed.rpcId === "string") rpcId = parsed.rpcId;
  } catch { /* not JSON / no rpcId: fall through */ }
  const { ok, value } = randomMeaninglessValue();
  await writeJson(res, 200, { type: "server-response", rpcId, result: { ok, value } });
}

async function forward(req, res, delegate, maxBytes) {
  const body = await readBody(req, maxBytes);
  const request = new Request(new URL(req.url || "/", "http://dsh.internal"), {
    method: req.method || "GET",
    headers: Object.fromEntries(Object.entries(req.headers).filter(([, v]) => typeof v === "string")),
    body: body.length ? body : undefined,
  });
  const response = await delegate.fetch(request);
  res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  const buf = Buffer.from(await response.arrayBuffer());
  res.end(buf);
}

function apply(ctx, config = {}) {
  const sec = ctx.get("security");
  if (!sec) {
    ctx.logger?.warn?.("[dsh-security.api-protect] 核心模块未挂载；本模块空闲");
    return;
  }
  const scoped = {};
  const alertedIps = new Set();

  ctx.inject(["webServer", "apiProxy"], (tctx) => {
    scoped.get = () => config;
    const delegate = toFetchHandler(tctx.apiProxy);
    const unregister = sec.registerModule({
      id: "api-protect",
      name: "API 保护",
      description: "对来自未登录或陌生 IP 的 /api/* 请求，返回随机无意义的数据以迷惑攻击者。",
      version: "0.1.0",
      category: "api",
      enabled: config.enabled !== false,
    });

    for (const method of API_METHODS) {
      const path = `/api/${method}`;
      const disposer = tctx.webServer.register({
        kind: "exact",
        path,
        handler: async (req, res) => {
          if (config.enabled === false) {
            return forward(req, res, delegate, config.maxRequestBodyBytes);
          }
          const ip = normalizeIp(req.socket?.remoteAddress);
          const trusted = isTrustedApiRequest(req, config.trustedHosts ?? []);
          const verdict = ip ? sec.ip.verdict(ip) : "trusted";
          const stranger = config.fakeStrangers !== false && !isLoopback(ip) && verdict === "stranger";

          if (stranger) {
            if (config.alertOnStranger !== false && !alertedIps.has(ip)) {
              alertedIps.add(ip);
              sec.alert({
                type: "api-protect:stranger-ip",
                ip,
                endpoint: method,
                details: `未登录/陌生 IP（${ip}）尝试访问 ${method}。若为正常用户，请在“安全中心”控制面板中将该 IP 加入可信列表。`,
                time: new Date().toISOString(),
              }).catch(() => {});
            }
            return fakeResponse(req, res);
          }

          if (!trusted || (PRIVILEGED_METHODS.has(method) && !isLoopback(ip))) {
            res.writeHead(403);
            res.end("forbidden");
            return;
          }
          return forward(req, res, delegate, config.maxRequestBodyBytes);
        },
      });
      tctx.effect(() => disposer, `dsh-security.api-protect route ${path}`);
    }

    tctx.effect(() => () => unregister(), "dsh-security.api-protect teardown");
  });
}

export { apply };
