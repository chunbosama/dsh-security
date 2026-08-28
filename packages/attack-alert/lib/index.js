import net from "node:net";
import tls from "node:tls";
import { createHash } from "node:crypto";
import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";

export const name = "security-attack-alert";
export const inject = ["security"];

export const NS = settingsNamespace("dsh-security-attack-alert");

export const Config = z.object({
  enabled: z.boolean().default(true),
  smtpHost: z.string().default(""),
  smtpPort: z.natural().max(65535).default(25),
  smtpUser: z.string().optional(),
  smtpPass: z.string().role("secret").optional(),
  from: z.string().default("dsh-security@localhost"),
  to: z.string().default(""),
  tls: z.boolean().default(false),        // STARTTLS
  implicitTls: z.boolean().default(false), // connect TLS from the first byte (465)
  timeoutMs: z.natural().default(15000),
});

/**
 * Minimal SMTP client. Deliberately dependency-free: DSH ships no mail seam,
 * so this module talks SMTP directly over node:net / node:tls (AUTH LOGIN,
 * optional STARTTLS, a single recipient, plain-text + HTML body).
 */
function readResponse(socket) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      // A response ends when we see a final line `NNN ` (space after the code)
      const idx = buffer.search(/\r?\n/);
      let lines = buffer.split(/\r?\n/);
      // keep partial last line
      buffer = lines.pop() ?? "";
      lines = lines.filter((l) => l.length > 0);
      for (const line of lines) {
        if (/^\d{3} /.test(line)) {
          cleanup();
          resolve({ code: Number(line.slice(0, 3)), text: line });
          return;
        }
      }
      void idx;
    };
    const onError = (err) => { cleanup(); reject(err); };
    const onClose = () => { cleanup(); reject(new Error("smtp: connection closed before response")); };
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

async function sendLine(socket, line) {
  await new Promise((resolve, reject) => {
    socket.write(line + "\r\n", (err) => (err ? reject(err) : resolve()));
  });
}

function expect(code, resp) {
  if (resp.code !== code) {
    throw new Error(`smtp: expected ${code} but got ${resp.code} ${resp.text.trim()}`);
  }
  return resp;
}

async function sendMail(cfg, message) {
  const port = cfg.smtpPort ?? 25;
  const timeout = cfg.timeoutMs ?? 15000;
  const connectOpts = { host: cfg.smtpHost, port };
  let socket = cfg.implicitTls
    ? tls.connect({ ...connectOpts, rejectUnauthorized: false })
    : net.connect(connectOpts);
  socket.setTimeout(timeout);

  const fail = (err) => {
    try { socket.destroy(); } catch {}
    throw err;
  };
  const step = async (line, want, label) => {
    const resp = await readResponse(socket).catch(fail);
    try {
      expect(want, resp);
    } catch (e) {
      return fail(new Error(`${label || line}: ${e.message}`));
    }
    return resp;
  };

  try {
    socket.on("timeout", () => fail(new Error("smtp: timeout waiting for server")));
    // greeting
    await step("connect", 220, "greeting");
    const ehlo = `EHLO ${cfg.ehloName || "dsh-security"}`;
    let ehloResp = await step(ehlo, 250, "EHLO");
    // STARTTLS upgrade if requested
    if (cfg.tls && !cfg.implicitTls) {
      await step("STARTTLS", 220, "STARTTLS");
      socket = tls.connect({ socket, rejectUnauthorized: false });
      socket.setTimeout(timeout);
      socket.on("timeout", () => fail(new Error("smtp: timeout after STARTTLS")));
      ehloResp = await step(ehlo, 250, "EHLO(over TLS)");
    }
    const extensions = ehloResp.text;
    const supportsAuth = /AUTH[ \t\r\n]|AUTH=[A-Z0-9-]+/.test(extensions) || cfg.smtpUser;
    if (supportsAuth && cfg.smtpUser && cfg.smtpPass) {
      await step("AUTH LOGIN", 334, "AUTH LOGIN");
      await step(Buffer.from(cfg.smtpUser).toString("base64"), 334, "AUTH user");
      await step(Buffer.from(cfg.smtpPass).toString("base64"), 235, "AUTH pass");
    }
    await step(`MAIL FROM:<${cfg.from}>`, 250, "MAIL FROM");
    await step(`RCPT TO:<${cfg.to}>`, 250, "RCPT TO");
    await step("DATA", 354, "DATA");
    await rawStep(`${message.headers}${message.body}\r\n.\r\n`, 250, "message body");
    await step("QUIT", 221, "QUIT");
  } finally {
    try { socket.destroy(); } catch {}
  }
}

function buildMessage(cfg, payload) {
  const time = payload.time || new Date().toISOString();
  const lines = [
    `攻击类型      : ${payload.type}`,
    `时间 (UTC)     : ${time}`,
    `来源 IP        : ${payload.ip || "未知"}`,
    `调用方 agent   : ${payload.agent || "未知"}`,
    `工具/命令      : ${payload.command || "无"}`,
    `文件路径       : ${payload.path || "无"}`,
    `API 端点       : ${payload.endpoint || "无"}`,
    ``,
    `详情：`,
    payload.details || "(无)",
  ];
  const text = lines.join("\n");
  const subject = `[dsh-security] ${payload.type}`;
  const escaped = text.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const html = `<pre style="font-family:monospace">${escaped}</pre>`;
  const boundary = `----=_dsh_security_${createHash("sha1").update(time).digest("hex").slice(0, 12)}`;
  const headers = [
    `From: ${cfg.from}`,
    `To: ${cfg.to}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ``,
  ].join("\r\n") + "\r\n";
  const body = [
    `--${boundary}`,
    `Content-Type: text/plain; charset=UTF-8`,
    ``,
    text,
    ``,
    `--${boundary}`,
    `Content-Type: text/html; charset=UTF-8`,
    ``,
    html,
    ``,
    `--${boundary}--`,
    ``,
  ].join("\r\n");
  return { headers, body };
}

function apply(ctx, config = {}) {
  const sec = ctx.get("security");
  if (!sec) {
    ctx.logger?.warn?.("[dsh-security.attack-alert] core not mounted; module idle");
    return;
  }
  const getCfg = () => {
    const s = ctx.get("settings");
    if (s && s.get(NS)) return s.get(NS);
    return config;
  };
  // optional live settings section
  ctx.inject(["settings"], (sctx) => {
    sctx.settings.register(NS, Config, { base: config });
  });

  const unregister = sec.registerModule({
    id: "attack-alert",
    name: "攻击提醒",
    description: "当其它安全模块触发保护时，向配置的邮箱发送一封 SMTP 邮件提醒管理员。",
    version: "0.1.0",
    category: "alert",
    enabled: config.enabled !== false,
    async handleAlert(payload) {
      const cfg = getCfg();
      if (cfg.enabled === false) return;
      if (!cfg.smtpHost || !cfg.to) {
        ctx.logger?.warn?.("[dsh-security.attack-alert] email not configured (smtpHost/to missing); skipping alert");
        return;
      }
      const message = buildMessage(cfg, payload);
      await sendMail(cfg, message);
      ctx.logger?.info?.(`[dsh-security.attack-alert] 告警已发送至 ${cfg.to} (${payload.type})`);
    },
  });
  ctx.effect(() => () => unregister(), "dsh-security.attack-alert teardown");
}

export { apply };
