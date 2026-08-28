/**
 * Control-panel client half.
 *
 * Registers a "Security" page under Settings (`settings.section` id `security`)
 * that:
 *   - lists every installed security module (read from the `dsh-security`
 *     settings namespace roster maintained by the core plugin),
 *   - lets the admin set/change the admin password (written as a pending,
 *     write-only field that the core hashes host-side), and
 *   - manages the trusted-IP allowlist.
 *
 * NOTE: this source is plain ES (no JSX/TypeScript) and must be bundled to
 * `lib/client.js` with the DSH client build pipeline (tsdown), like every
 * other dsh client plugin. The `window.__ModuleLoader__.load(...)` wrapper is
 * produced by that build; it is not hand-authored here.
 */
import React from "react";

const NS = "dsh-security";
const NS_LABEL = "Security";

function apply(ctx) {
  const scope = ctx.settingsScope.bind({ namespace: NS });
  const t = ctx.locale ? ctx.locale.bind("settings.security") : (s) => s;

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

  return React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 20, maxWidth: 640 } },
    React.createElement("section", null,
      React.createElement("h3", null, "Admin password"),
      hasPassword
        ? React.createElement("p", null, "An admin password is configured.")
        : React.createElement("p", null, "No admin password is set. Set one to enable password-gated protections."),
      React.createElement("form", { onSubmit: onSetPassword, style: { display: "flex", gap: 8 } },
        React.createElement("input", {
          type: "password", value: pw, placeholder: "New admin password",
          onChange: (e) => setPw(e.target.value), style: { flex: 1 },
        }),
        React.createElement("button", { type: "submit" }, hasPassword ? "Change password" : "Set password"),
      ),
    ),
    React.createElement("section", null,
      React.createElement("h3", null, "Installed security modules"),
      modules.length === 0
        ? React.createElement("p", null, "No security modules are installed.")
        : React.createElement("ul", null,
            modules.map((m) => React.createElement("li", { key: m.id },
              React.createElement("strong", null, m.name || m.id),
              m.description ? React.createElement("span", { style: { marginLeft: 8, opacity: 0.7 } }, m.description) : null,
            ))),
    ),
    React.createElement("section", null,
      React.createElement("h3", null, "Trusted IPs"),
      trustedIps.length === 0
        ? React.createElement("p", null, "No trusted IPs added.")
        : React.createElement("ul", null,
            trustedIps.map((ip) => React.createElement("li", { key: ip },
              ip,
              React.createElement("button", { onClick: () => security.actions.unmarkTrusted(ip), style: { marginLeft: 8 } }, "Remove"),
            ))),
      React.createElement("form", { onSubmit: onAddTrusted, style: { display: "flex", gap: 8 } },
        React.createElement("input", {
          type: "text", value: newIp, placeholder: "IP address (e.g. 192.168.1.5)",
          onChange: (e) => setNewIp(e.target.value), style: { flex: 1 },
        }),
        React.createElement("button", { type: "submit" }, "Add trusted IP"),
      ),
    ),
  );
}

export { apply };
