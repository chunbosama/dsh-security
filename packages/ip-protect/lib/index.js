import z from "@deepseek-ai/schemastery";

export const name = "security-ip-protect";
export const inject = ["security"];

export const Config = z.object({
  enabled: z.boolean().default(true),
  alertOnStrangerConversation: z.boolean().default(true),
  // endpoint paths (relative to /api/) that count as "starting a conversation"
  conversationEndpoints: z.array(z.string()).default(["session.prompt"]),
  alertOnceMs: z.natural().default(30 * 60 * 1000), // don't re-email the same IP more than once per window
});

function normalizeIp(ip) {
  if (!ip) return "";
  return ip.replace(/^::ffff:/, "");
}

function isLoopback(ip) {
  return ip === "127.0.0.1" || ip === "::1" || ip === "" || ip.startsWith("127.");
}

function apply(ctx, config = {}) {
  const sec = ctx.get("security");
  if (!sec) {
    ctx.logger?.warn?.("[dsh-security.ip-protect] 核心模块未挂载；本模块空闲");
    return;
  }
  const alerted = new Map(); // ip -> timestamp
  const endpoints = new Set(config.conversationEndpoints ?? ["session.prompt"]);

  ctx.inject(["webServer"], (tctx) => {
    const unregister = sec.registerModule({
      id: "ip-protect",
      name: "陌生 IP 保护",
      description: "通过分析 /api 流量学习常用 IP，发现陌生 IP 发起对话时发邮件提醒管理员将 IP 加入可信列表。",
      version: "0.1.0",
      category: "ip",
      enabled: config.enabled !== false,
    });

    const handleRequest = (req, kind) => {
      if (config.enabled === false) return;
      const url = req.url || "/";
      if (!url.startsWith("/api/")) return;
      const ip = normalizeIp(req.socket?.remoteAddress);
      if (!ip) return;
      // record every API access so the common-IP model learns
      sec.ip.record(ip);

      const pathname = url.split("?")[0];
      const method = pathname.startsWith("/api/") ? pathname.slice(5) : null;
      if (isLoopback(ip)) return;
      if (sec.ip.verdict(ip) !== "stranger") return; // trusted or common user

      const isConversation = method !== null && endpoints.has(method);
      if (!isConversation && kind !== "upgrade") return;

      const now = Date.now();
      const last = alerted.get(ip);
      if (last !== undefined && now - last < (config.alertOnceMs ?? 30 * 60 * 1000)) return;
      alerted.set(ip, now);

      sec.alert({
        type: "stranger-ip-conversation",
        ip,
        endpoint: method || "WebSocket",
        details: `陌生 IP（${ip}）在 ${method || "WebSocket"} 上发起了一次对话（${kind}）。` +
          `若为正常用户，请在“安全中心”控制面板中将 ${ip} 加入可信 IP 列表；` +
          `在此之前，其请求将被返回无意义的数据。`,
        time: new Date().toISOString(),
      }).catch(() => {});
    };

    const server = tctx.webServer.server;
    const onRequest = (req) => handleRequest(req, "request");
    const onUpgrade = (req) => handleRequest(req, "upgrade");

    tctx.effect(() => {
      server.on("request", onRequest);
      server.on("upgrade", onUpgrade);
      return () => {
        server.off("request", onRequest);
        server.off("upgrade", onUpgrade);
      };
    }, "dsh-security.ip-protect observer");

    tctx.effect(() => () => unregister(), "dsh-security.ip-protect teardown");
  });
}

export { apply };
