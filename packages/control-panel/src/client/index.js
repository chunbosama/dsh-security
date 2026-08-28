/**
 * 控制面板 - 浏览器端实现。
 *
 * 在“设置”中注册“安全中心”页面（settings.section，id=security），实现：
 *   - 列出所有已安装的安全模块（读取核心插件维护在 dsh-security 设置命名空间中的模块清单）；
 *   - 设置/修改管理员密码（写入 pending 明文字段，由核心插件在服务端哈希存储）；
 *   - 维护可信 IP 列表。
 *
 * 说明：本源码为纯 ES（无 JSX/TypeScript），需像其它 dsh 客户端插件一样，通过 DSH 客户端构建
 * 管线（tsdown）打包为 lib/client.js（其 window.__ModuleLoader__.load(...) 包装由构建产生）。
 */
import React from "react";

const NS = "dsh-security";
const NS_LABEL = "安全中心";

function apply(ctx) {
  const scope = ctx.settingsScope.bind({ namespace: NS });

  const face = () => ({ hooks: { security: {
    getSnapshot: () => scope.getSnapshot(),
    subscribe: (listener) => scope.subscribe(listener),
    actions: {
      setPassword(pw) { return scope.set("adminPasswordPending", pw); },
      clearPassword() { return scope.unset("adminPasswordHash"); },
      markTrusted(ip) {
        const value = scope.getSnapshot().value;
        const trusted = Array.isArray(value.trustedIps) ? value.trustedIps : [];
        if (!trusted.includes(ip)) return scope.set("trustedIps", [...trusted, ip]);
        return Promise.resolve();
      },
      unmarkTrusted(ip) {
        const value = scope.getSnapshot().value;
        const trusted = Array.isArray(value.trustedIps) ? value.trustedIps : [];
        return scope.set("trustedIps", trusted.filter((x) => x !== ip));
      },
    },
  } } });

  ctx.slots.inject("settings.section", () => ctx.slots.register({
    name: "settings.section",
    id: "security",
    order: 25,
    label: () => NS_LABEL,
    locale: "settings.security",
    inject: face,
  }, SecuritySection));
}

function SecuritySection(props) {
  const security = props.hooks.security;
  const snap = React.useSyncExternalStore(security.subscribe, security.getSnapshot);
  const value = (snap && snap.value) || {};
  const modules = Array.isArray(value.modules) ? value.modules : [];
  const trustedIps = Array.isArray(value.trustedIps) ? value.trustedIps : [];
  const hasPassword = Boolean(value.adminPasswordHash);
  const [pw, setPw] = React.useState("");
  const [newIp, setNewIp] = React.useState("");

  const onSetPassword = (e) => {
    e.preventDefault();
    if (!pw) return;
    security.actions.setPassword(pw).then(() => setPw(""));
  };

  const onAddTrusted = (e) => {
    e.preventDefault();
    if (!newIp) return;
    security.actions.markTrusted(newIp.trim()).then(() => setNewIp(""));
  };

  const rowStyle = { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid var(--dsw-alias-border, #eee)" };

  return React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 24, maxWidth: 680 } },
    React.createElement("section", null,
      React.createElement("h3", null, "管理员密码"),
      hasPassword
        ? React.createElement("p", null, "已配置管理员密码。")
        : React.createElement("p", null, "尚未设置管理员密码。设置后即可启用基于密码的安全防护。"),
      React.createElement("form", { onSubmit: onSetPassword, style: { display: "flex", gap: 8 } },
        React.createElement("input", {
          type: "password", value: pw, placeholder: "新管理员密码",
          onChange: (e) => setPw(e.target.value), style: { flex: 1 },
        }),
        React.createElement("button", { type: "submit" }, hasPassword ? "修改密码" : "设置密码"),
      ),
    ),

    React.createElement("section", null,
      React.createElement("h3", null, "已安装的安全模块"),
      modules.length === 0
        ? React.createElement("p", null, "尚未安装任何安全模块。")
        : React.createElement("ul", { style: { listStyle: "none", margin: 0, padding: 0 } },
            modules.map((m) => React.createElement("li", { key: m.id, style: rowStyle },
              React.createElement("strong", null, m.name || m.id),
              m.description
                ? React.createElement("span", { style: { marginLeft: 8, opacity: 0.7, fontSize: 13 } }, m.description)
                : null,
            ))),
    ),

    React.createElement("section", null,
      React.createElement("h3", null, "可信 IP 列表"),
      trustedIps.length === 0
        ? React.createElement("p", null, "尚未添加可信 IP。")
        : React.createElement("ul", { style: { listStyle: "none", margin: 0, padding: 0 } },
            trustedIps.map((ip) => React.createElement("li", { key: ip, style: rowStyle },
              React.createElement("code", null, ip),
              React.createElement("button", { onClick: () => security.actions.unmarkTrusted(ip) }, "移除"),
            ))),
      React.createElement("form", { onSubmit: onAddTrusted, style: { display: "flex", gap: 8 } },
        React.createElement("input", {
          type: "text", value: newIp, placeholder: "IP 地址（例如 192.168.1.5）",
          onChange: (e) => setNewIp(e.target.value), style: { flex: 1 },
        }),
        React.createElement("button", { type: "submit" }, "添加可信 IP"),
      ),
    ),
  );
}

export { apply };
