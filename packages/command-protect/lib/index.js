import z from "@deepseek-ai/schemastery";
import { settingsNamespace } from "@deepseek-ai/dsh-settings";
import { defineTool } from "@deepseek-ai/dsh-tools";

export const name = "security-command-protect";
export const inject = ["security"];

export const NS = settingsNamespace("dsh-security-command-protect");

export const Config = z.object({
  enabled: z.boolean().default(true),
  dangerThreshold: z.natural().max(100).default(50),
  // 额外的自定义规则：{ name, pattern（正则字符串）, score }
  rules: z.array(z.object({
    name: z.string(),
    pattern: z.string(),
    score: z.natural().max(100).default(50),
  })).default([]),
});

const DEFAULT_RULES = [
  { name: "删除根目录", pattern: /rm\s+(-[a-z]*[rR][a-z]*\s+)+(-f\b|\s*\/\b)/.source, score: 100 },
  { name: "fork 炸弹", pattern: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/.source, score: 100 },
  { name: "格式化磁盘", pattern: /\bmkfs(\.\w+)?\b/.source, score: 100 },
  { name: "写入原始磁盘设备", pattern: /\bdd\b(?=[^|]*\b(if|of)=[^ |]*\/dev\/(sd|hd|nvme))/.source, score: 100 },
  { name: "磁盘分区工具", pattern: /\b(fdisk|parted|gdisk|wipefs|shred)\b/.source, score: 80 },
  { name: "关机/重启", pattern: /\b(shutdown|reboot|halt|poweroff|init\s+0)\b/.source, score: 90 },
  { name: "递归修改根目录权限", pattern: /\bchmod\s+(-R\s+)?[0-7]{3}\s+\//.source, score: 90 },
  { name: "递归修改根目录属主", pattern: /\bchown\s+(-R\s+)?[^ ]+\s+\//.source, score: 90 },
  { name: "写入原始磁盘", pattern: /(>>?|>)\s*\/dev\/(sd|hd|nvme)/.source, score: 100 },
  { name: "下载并管道执行 shell", pattern: /(wget|curl|nc|aria2c)\b[^|;\n]*\|\s*(ba|z|c)?sh\b/.source, score: 90 },
  { name: "eval 执行", pattern: /\beval\b/.source, score: 60 },
  { name: "解码后执行 shell", pattern: /(base64|xxd|od)\b[^|;]*(\||>)[^|;]*(ba|z)?sh/.source, score: 80 },
  { name: "强制结束进程", pattern: /\bkill\s+-9\b/.source, score: 50 },
  { name: "递归删除", pattern: /\brm\s+-[a-z]*[rR][a-z]*\b/.source, score: 55 },
  { name: "提权 sudo", pattern: /\bsudo\b/.source, score: 40 },
  { name: "防火墙操作", pattern: /\b(iptables|ufw|nft)\b/.source, score: 60 },
  { name: "PowerShell 破坏性操作", pattern: /(Remove-Item\s+-Recurse|Format-Volume|Clear-Disk|Initialize-Disk|Restart-Computer|Stop-Computer|Set-ExecutionPolicy|Disable-Autologon)/.source, score: 90 },
];

/** 返回某条命令的危险评分 { score, matched }。 */
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
    ctx.logger?.warn?.("[dsh-security.command-protect] 核心模块未挂载；本模块空闲");
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
        reason: `该命令已被安全策略拦截（危险评分 ${score}：${name || "危险操作"}）：${command}。` +
          `如你已被授权，请调用 security_verify_password 工具输入管理员密码以解锁危险命令，然后重试；` +
          `否则请改用更安全的替代方案。`,
      };
    };

    // 在工具执行前置检查点拦截（所有 shell 命令工具都会经过这里）。
    const off = tctx.on("tools/pre-execute", async (exec, next) => {
      if (!COMMAND_TOOLS.has(exec.name)) return next();
      const decision = gate(exec);
      if (decision.allow) return next();
      return { kind: "deny", reason: decision.reason };
    }, { prepend: true });

    // 纵深防御：同时拦截直接调用 ctx.shell 的调用方（cordis SDK、其他插件）。
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

    // 模型在遇到危险命令时调用此工具，输入管理员密码以解锁。
    tctx.tools.register(defineTool({
      name: "security_verify_password",
      description: "验证管理员密码并解锁危险命令执行（限时窗口）。会向用户询问管理员密码。",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute(args, exec) {
        const secNow = ctx.get("security");
        const questions = ctx.get("userQuestions");
        if (!secNow || !questions) return { ok: false, error: "安全服务不可用" };
        let answer;
        try {
          answer = await questions.ask({
            questions: [{
              id: "adminPassword",
              question: "请输入管理员密码以解锁危险命令执行。",
              header: "安全验证",
              detail: "密码验证通过后，危险命令执行将在短时间内解锁。",
            }],
            agent: exec.agent,
          });
        } catch (error) {
          return { ok: false, error: `提示被取消：${String(error)}` };
        }
        const value = answer?.answers?.[0];
        const password = value?.custom ?? value?.selected?.[0];
        if (!password) return { ok: false, error: "未提供管理员密码。" };
        const valid = await secNow.password.verify(String(password));
        if (!valid) return { ok: false, error: "管理员密码错误。" };
        secNow.securitySession.unlock();
        ctx.logger?.info?.("[dsh-security.command-protect] 管理员密码验证通过，已解锁危险命令");
        return { ok: true, message: "管理员密码验证通过。危险命令执行已解锁（限时窗口）。" };
      },
    }));

    tctx.tools.register(defineTool({
      name: "security_lock",
      description: "立即锁定危险命令执行（与 security_verify_password 相反）。无需参数。",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute() {
        const secNow = ctx.get("security");
        if (secNow) secNow.securitySession.lock();
        return { ok: true, message: "危险命令执行已锁定。" };
      },
    }));

    const unregister = sec.registerModule({
      id: "command-protect",
      name: "命令执行防护",
      description: "检测危险命令，并要求在危险命令执行前输入管理员密码。",
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
