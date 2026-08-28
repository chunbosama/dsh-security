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
    ctx.logger?.warn?.("[dsh-security.ip-protect] core not mounted; module idle");
    return;
  }
  const alerted = new Map(); // ip -> timestamp
  const endpoints = new Set(config.conversationEndpoints ?? ["session.prompt"]);

  ctx.inject(["webServer"], (tctx) => {
    const unregister = sec.registerModule({
      id: "ip-protect",
      name: "陌生 IP 保护 (Strange IP Protection)",
      description: "Learns common IPs from /api traffic, flags stranger conversations and emails the admin to add the IP to the trusted list.",
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
        endpoint: method || "(websocket)",
        details: `A stranger IP (${ip}) started a conversation on ${method || "the websocket"} (${kind}). ` +
          `If this is a legitimate user, add ${ip} to the trusted IP list in the Security control panel. ` +
          `Until then, its requests are answered with meaningless data.`,
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
