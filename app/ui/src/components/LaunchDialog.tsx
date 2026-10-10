// Capture → Start Browser… / Open Terminal: programs that send their traffic through Quena
// without the system proxy (own browser profile; proxy and certificate variables).
import { useEffect, useState } from "react";
import { api, type BrowserInfo } from "../api";
import { promptText, say, set } from "../store";
import { showContextMenu } from "./ContextMenu";
import { t } from "../i18n";

export async function startBrowser(b: BrowserInfo, url?: string) {
  try {
    await api.launchBrowser(b.kind, url);
    say(t("{name} started with Quena as proxy", { name: b.name }));
  } catch (e) {
    say(String(e), "error");
  }
}

export async function openTerminal() {
  try {
    await api.openTerminal();
    say(t("Terminal opened: proxy and root certificate are set for its tools"));
  } catch (e) {
    say(String(e), "error");
  }
}

/** Start an AI agent (Claude Code, Codex, Gemini CLI …) in a terminal that uses Quena. */
export async function startAgent(command?: string) {
  const c = command ?? (await promptText(t("Start Agent"), t("Command of the agent, e.g. claude, codex, gemini — it starts in a terminal whose proxy and root certificate are Quena's"), "claude"));
  if (!c?.trim()) return;
  try {
    await api.startAgent(c.trim());
    say(t("{name} started in a terminal that uses Quena; its calls show in the Agents panel", { name: c.trim() }));
  } catch (e) {
    say(String(e), "error");
  }
}

/** The toolbar's menu: one entry per installed browser, then the terminal. */
export async function launchMenu(x: number, y: number) {
  const browsers = await api.browsersList().catch(() => [] as BrowserInfo[]);
  showContextMenu(x, y, [
    ...(browsers.length
      ? browsers.map((b) => ({ label: t("Start {name}", { name: b.name }), action: () => void startBrowser(b) }))
      : [{ label: t("No supported browser found"), disabled: true }]),
    { separator: true },
    { label: t("Open Terminal"), action: () => void openTerminal() },
    { label: t("Start Claude Code"), action: () => void startAgent("claude") },
    { label: t("Start Codex"), action: () => void startAgent("codex") },
    { label: t("Start Agent…"), action: () => void startAgent() },
    { separator: true },
    { label: t("Start with URL…"), action: () => set({ dialog: { kind: "launch" } }) },
  ]);
}

export function LaunchPanel() {
  const [browsers, setBrowsers] = useState<BrowserInfo[] | null>(null);
  const [url, setUrl] = useState("");
  useEffect(() => {
    api.browsersList().then(setBrowsers, () => setBrowsers([]));
  }, []);
  return (
    <div className="launch">
      <p className="muted small">
        {t("Starts a program whose traffic goes through Quena, without changing the system proxy. Capturing starts if it is off.")}
      </p>
      <div className="f-row">
        <span>{t("Start URL")}</span>
        <input value={url} placeholder="https://example.com" spellCheck={false} autoCorrect="off" autoCapitalize="off" onChange={(e) => setUrl(e.target.value)} />
      </div>
      <div className="launch-list">
        {browsers === null && <span className="muted">{t("Looking for browsers…")}</span>}
        {browsers?.length === 0 && <span className="muted">{t("No supported browser found")}</span>}
        {browsers?.map((b) => (
          <button key={b.kind} title={b.exe} onClick={() => void startBrowser(b, url.trim() || undefined).then(() => set({ dialog: null }))}>
            {b.name}
          </button>
        ))}
        <button onClick={() => void openTerminal().then(() => set({ dialog: null }))}>{t("Open Terminal")}</button>
      </div>
      <p className="muted small">
        {t("Chrome, Edge, Brave and Vivaldi get their own profile and accept Quena's certificates in it. Firefox uses the system's trusted roots: trust the Quena root certificate first (Capture → HTTPS Settings…). The terminal sets HTTP_PROXY, HTTPS_PROXY and the root certificate for Node.js, Python, curl, Git and others.")}
      </p>
    </div>
  );
}
