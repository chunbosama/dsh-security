import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";
import { defineTool } from "@deepseek-ai/dsh-tools";

export const name = "security-command-protect";
export const inject = ["security"];

export const NS = settingsNamespace("dsh-security-command-protect");

export const Config = z.object({
  enabled: z.boolean().default(true),
  dangerThreshold: z.natural().max(100).default(50),
  // additional custom rules: { name, pattern (regex source), score }
  rules: z.array(z.object({
    name: z.string(),
    pattern: z.string(),
    score: z.natural().max(100).default(50),
  })).default([]),
});

const DEFAULT_RULES = [
  { name: "rm -rf /", pattern: /rm\s+(-[a-z]*[rR][a-z]*\s+)+(-f\b|\s*\/\b)/.source, score: 100 },
  { name: "fork bomb", pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/.source, score: 100 },
  { name: "mkfs", pattern: /\bmkfs(\.\w+)?\b/.source, score: 100 },
  { name: "dd raw device", pattern: /\bdd\b(?=[^|]*\b(if|of)=[^ |]*\/dev\/(sd|hd|nvme))/.source, score: 100 },
  { name: "partition tool", pattern: /\b(fdisk|parted|gdisk|wipefs|shred)\b/.source, score: 80 },
  { name: "power ops", pattern: /\b(shutdown|reboot|halt|poweroff|init\s+0)\b/.source, score: 90 },
  { name: "chmod -R /", pattern: /\bchmod\s+(-R\s+)?[0-7]{3}\s+\//.source, score: 90 },
  { name: "chown -R /", pattern: /\bchown\s+(-R\s+)?[^ ]+\s+\//.source, score: 90 },
  { name: "write to raw disk", pattern: /(>>?|>)\s*\/dev\/(sd|hd|nvme)/.source, score: 100 },
  { name: "pipe download to shell", pattern: /(wget|curl|nc|aria2c)\b[^|;\n]*\|\s*(ba|z|c)?sh\b/.source, score: 90 },
  { name: "eval", pattern: /\beval\b/.source, score: 60 },
  { name: "base64 decode to shell", pattern: /(base64|xxd|od)\b[^|;]*(\||>)[^|;]*(ba|z)?sh/.source, score: 80 },
  { name: "kill -9", pattern: /\bkill\s+-9\b/.source, score: 50 },
  { name: "recursive rm", pattern: /\brm\s+-[a-z]*[rR][a-z]*\b/.source, score: 55 },
  { name: "sudo", pattern: /\bsudo\b/.source, score: 40 },
  { name: "firewall", pattern: /\b(iptables|ufw|nft)\b/.source, score: 60 },
  { name: "powershell destructive", pattern: /(Remove-Item\s+-Recurse|Format-Volume|Clear-Disk|Initialize-Disk|Restart-Computer|Stop-Computer|Set-ExecutionPolicy|Disable-Autologon)/.source, score: 90 },
];

/** Returns { score, matched } for a command string. */
function scoreCommand(command, extraRules) {
  const rules = extraRules && extraRules.length
    ? [...DEFAULT_RULES, ...extraRules.map((r) => ({ ...r, pattern: r.pattern }))]
    : DEFAULT_RULES;
  let best = { score: 0, name: null };
  for (const rule of rules) {
    let re;
    try { re = new RegExp(rule.pattern, "i"); } catch { continue; }
    if (re.test(command) && rule.score > best.score) {
      best = { score: rule.score, name: rule.name };
    }
  }
  return best;
}

const COMMAND_TOOLS = new Set(["bash", "pwsh", "powershell.exe", "powershell", "terminal"]);

function apply(ctx, config = {}) {
  const sec = ctx.get("security");
  if (!sec) {
    ctx.logger?.warn?.("[dsh-security.command-protect] core not mounted; module idle");
    return;
  }
  const scoped = {};
  ctx.inject(["settings", "tools", "userQuestions"], (tctx) => {
    const scope = tctx.settings.register(NS, Config, { base: config });
    scoped.get = () => scope.get() ?? config;

    const isDangerous = (command, cfg) => {
      const { score, name } = scoreCommand(command, cfg.rules);
      return { dangerous: score >= (cfg.dangerThreshold ?? 50), score, name };
    };

    const gate = (exec) => {
      const cfg = scoped.get();
      if (cfg.enabled === false) return { allow: true };
      const command = typeof exec?.arguments?.command === "string" ? exec.arguments.command : null;
      if (!command) return { allow: true };
      const { dangerous, score, name } = isDangerous(command, cfg);
      if (!dangerous) return { allow: true };
      if (sec.securitySession.isUnlocked()) return { allow: true, score, name };
      return {
        allow: false,
        score,
        name,
        reason: `This command was blocked by the security policy (danger score ${score}: ${name || "dangerous"}): ${command}. ` +
          `If you are authorized, call the security_verify_password tool to enter the admin password and unlock dangerous commands, then retry. ` +
          `Otherwise use a safer alternative.`,
      };
    };

    // Primary gate at the tool choke point. Only shell command tools are
    // evaluated (the gate itself stays name-agnostic so the shell wrapper can
    // reuse it for direct ctx.shell callers).
    const off = tctx.on("tools/pre-execute", async (exec, next) => {
      if (!COMMAND_TOOLS.has(exec.name)) return next();
      const decision = gate(exec);
      if (decision.allow) return next();
      return { kind: "deny", reason: decision.reason };
    }, { prepend: true });

    // Defense-in-depth: also gate direct ctx.shell callers (cordis SDK, plugins).
    const shell = tctx.get("shell");
    const restoreShell = [];
    if (shell && typeof shell.run === "function") {
      const originalRun = shell.run.bind(shell);
      const originalStart = shell.start?.bind?.(shell);
      shell.run = async (spec) => {
        const decision = gate({ arguments: { command: spec?.command } });
        if (decision.allow) return originalRun(spec);
        throw new Error(decision.reason);
      };
      if (originalStart) {
        shell.start = (spec) => {
          const decision = gate({ arguments: { command: spec?.command } });
          if (decision.allow) return originalStart(spec);
          throw new Error(decision.reason);
        };
        restoreShell.push(() => { shell.start = originalStart; });
      }
      restoreShell.push(() => { shell.run = originalRun; });
    }

    // Tool the model calls to unlock dangerous commands with the admin password.
    tctx.tools.register(defineTool({
      name: "security_verify_password",
      description: "Verify the admin password and unlock dangerous-command execution for a short window. Prompts the human for the admin password.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute(args, exec) {
        const secNow = ctx.get("security");
        const questions = ctx.get("userQuestions");
        if (!secNow || !questions) return { ok: false, error: "security service unavailable" };
        let answer;
        try {
          answer = await questions.ask({
            questions: [{
              id: "adminPassword",
              question: "Enter the admin password to unlock dangerous commands.",
              header: "Security verification",
              detail: "Dangerous-command execution will be unlocked for a short window after the password is verified.",
            }],
            agent: exec.agent,
          });
        } catch (error) {
          return { ok: false, error: `prompt aborted: ${String(error)}` };
        }
        const value = answer?.answers?.[0];
        const password = value?.custom ?? value?.selected?.[0];
        if (!password) return { ok: false, error: "No admin password provided." };
        const valid = await secNow.password.verify(String(password));
        if (!valid) return { ok: false, error: "Incorrect admin password." };
        secNow.securitySession.unlock();
        ctx.logger?.info?.("[dsh-security.command-protect] admin password verified; dangerous commands unlocked");
        return { ok: true, message: "Admin password verified. Dangerous commands are now unlocked for a short window." };
      },
    }));

    tctx.tools.register(defineTool({
      name: "security_lock",
      description: "Immediately lock dangerous-command execution (the inverse of security_verify_password). No arguments.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute() {
        const secNow = ctx.get("security");
        if (secNow) secNow.securitySession.lock();
        return { ok: true, message: "Dangerous-command execution locked." };
      },
    }));

    const unregister = sec.registerModule({
      id: "command-protect",
      name: "命令执行防护 (Command Execution Protection)",
      description: "Detects dangerous commands and requires the admin password before they may run.",
      version: "0.1.0",
      category: "command",
      enabled: scoped.get().enabled !== false,
    });

    tctx.effect(() => () => {
      off();
      unregister();
      for (const restore of restoreShell) restore();
    }, "dsh-security.command-protect teardown");
  });
}

export { apply };
