// Filters tab. Changes apply live (debounced).
import { useEffect, useRef, useState } from "react";
import { api, type FilterSettings } from "../api";
import { get, promptText, say, set, useStore } from "../store";
import { actions } from "../actions";
import { t } from "../i18n";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <fieldset className="f-section">
      <legend>{title}</legend>
      {children}
    </fieldset>
  );
}

function Check({ label, value, onChange }: { label: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="f-check">
      <input type="checkbox" checked={value} onChange={(e) => onChange(e.target.checked)} /> {label}
    </label>
  );
}

/** Named filters: save the current settings under a name, apply, rename or delete them; each
 * shows how many sessions it would show. */
function SavedFilters({ current, apply }: { current: FilterSettings; apply: (f: FilterSettings) => void }) {
  const saved = useStore((s) => s.layout.savedFilters) ?? [];
  const version = useStore((s) => s.listVersion);
  const [counts, setCounts] = useState<(number | string)[]>([]);
  const [pick, setPick] = useState("");
  useEffect(() => {
    if (!saved.length) return setCounts([]);
    const timer = window.setTimeout(() => {
      api.countFilters(saved.map((x) => x.filters)).then(
        (r) => setCounts(r.map((x) => ("Ok" in x ? x.Ok : x.Err))),
        () => setCounts([]),
      );
    }, 400);
    return () => window.clearTimeout(timer);
  }, [saved, version]);
  const store = (list: { name: string; filters: FilterSettings }[]) => {
    set((s) => ({ layout: { ...s.layout, savedFilters: list } }));
    actions.saveLayout();
  };
  const i = saved.findIndex((x) => x.name === pick);
  return (
    <div className="f-saved">
      <select value={pick} onChange={(e) => setPick(e.target.value)} title={t("Saved filters")}>
        <option value="">{t("Saved filters…")}</option>
        {saved.map((x, j) => (
          <option key={x.name} value={x.name}>
            {x.name}
            {typeof counts[j] === "number" ? ` (${counts[j]})` : typeof counts[j] === "string" ? " (!)" : ""}
          </option>
        ))}
      </select>
      <button disabled={i < 0} onClick={() => i >= 0 && apply({ ...saved[i].filters, enabled: true })}>
        {t("Apply")}
      </button>
      <button
        onClick={async () => {
          const name = (await promptText(t("Save filter"), t("Name of the filter"), pick || ""))?.trim();
          if (!name) return;
          const list = get().layout.savedFilters ?? [];
          const rest = list.filter((x) => x.name !== name);
          store([...rest, { name, filters: { ...current } }].sort((a, b) => a.name.localeCompare(b.name)));
          setPick(name);
          say(t("Filter {name} saved", { name }));
        }}
      >
        {t("Save as…")}
      </button>
      <button
        disabled={i < 0}
        onClick={async () => {
          if (i < 0) return;
          const name = (await promptText(t("Rename filter"), t("Name of the filter"), saved[i].name))?.trim();
          if (!name || name === saved[i].name) return;
          store(saved.map((x, j) => (j === i ? { ...x, name } : x)).filter((x, j) => j === i || x.name !== name));
          setPick(name);
        }}
      >
        {t("Rename…")}
      </button>
      <button disabled={i < 0} onClick={() => i >= 0 && store(saved.filter((_, j) => j !== i))}>
        {t("Delete")}
      </button>
      {i >= 0 && typeof counts[i] === "string" && <span className="err small">{counts[i]}</span>}
    </div>
  );
}

export function FiltersPanel() {
  const stored = useStore((s) => s.filters);
  const [f, setF] = useState<FilterSettings | null>(stored);
  const [err, setErr] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => setF(stored), [stored]);

  if (!f) return <div className="placeholder">{t("Loading…")}</div>;

  const update = (patch: Partial<FilterSettings>) => {
    const next = { ...f, ...patch };
    setF(next);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(async () => {
      try {
        await api.setFilters(next);
        set({ filters: next });
        setErr(null);
        setTimeout(() => actions.refocus(), 80);
      } catch (e) {
        setErr(String(e));
      }
    }, 250);
  };
  const dis = !f.enabled;
  const num = (v: string) => (v.trim() === "" ? null : Math.max(0, Number(v)));

  return (
    <div className="scroll pad filters">
      <div className="f-top">
        <label className="f-check strong">
          <input type="checkbox" checked={f.enabled} onChange={(e) => update({ enabled: e.target.checked })} /> {t("Use Filters")}
        </label>
        <button
          onClick={() => {
            const reset: FilterSettings = { ...f, enabled: false, hostMode: "noFilter", hosts: "", processMode: "all", processOnly: "", hideProcesses: "", urlShowOnly: "", urlHide: "", hideConnects: false, hideSuccess: false, hideNonSuccess: false, hideAuth: false, hideRedirects: false, hideNotModified: false, hideImages: false, hideCss: false, hideScripts: false, hideFonts: false, contentTypeShowOnly: "", contentTypeHide: "", minSize: null, maxSize: null, minDurationMs: null, expression: "" };
            update(reset);
            say(t("Filters reset"));
          }}
        >
          {t("Reset")}
        </button>
        {err && <span className="err">{err}</span>}
      </div>
      <SavedFilters current={f} apply={(x) => update(x)} />
      <fieldset disabled={dis} className="f-body">
        <Section title={t("Hosts")}>
          <select value={f.hostMode} onChange={(e) => update({ hostMode: e.target.value as FilterSettings["hostMode"] })}>
            <option value="noFilter">{t("- No Host Filter -")}</option>
            <option value="showOnly">{t("Show only the following Hosts")}</option>
            <option value="hide">{t("Hide the following Hosts")}</option>
          </select>
          <textarea rows={3} placeholder="*.company.de; localhost; api.example.com" value={f.hosts} onChange={(e) => update({ hosts: e.target.value })} />
        </Section>
        <Section title={t("Client Process")}>
          <div className="f-radios">
            {(
              [
                ["all", t("All processes")],
                ["browsers", t("Show only browser traffic")],
                ["nonBrowsers", t("Show only non-browser traffic")],
                ["remote", t("Show only remote clients")],
              ] as const
            ).map(([k, l]) => (
              <label key={k} className="f-check">
                <input type="radio" checked={f.processMode === k} onChange={() => update({ processMode: k })} /> {l}
              </label>
            ))}
          </div>
          <div className="f-row">
            <span>{t("Show only traffic from")}</span>
            <input value={f.processOnly} placeholder="chrome; java" onChange={(e) => update({ processOnly: e.target.value })} />
          </div>
          <div className="f-row">
            <span>{t("Hide traffic from")}</span>
            <input value={f.hideProcesses} placeholder="Teams; OneDrive" onChange={(e) => update({ hideProcesses: e.target.value })} />
          </div>
        </Section>
        <Section title={t("Request Headers")}>
          <div className="f-row">
            <span>{t("Show only if URL contains")}</span>
            <input value={f.urlShowOnly} onChange={(e) => update({ urlShowOnly: e.target.value })} />
          </div>
          <div className="f-row">
            <span>{t("Hide if URL contains")}</span>
            <input value={f.urlHide} onChange={(e) => update({ urlHide: e.target.value })} />
          </div>
          <Check label={t("Hide CONNECT tunnels")} value={f.hideConnects} onChange={(v) => update({ hideConnects: v })} />
        </Section>
        <Section title={t("Response Status Code")}>
          <Check label={t("Hide success (2xx)")} value={f.hideSuccess} onChange={(v) => update({ hideSuccess: v })} />
          <Check label={t("Hide non-2xx")} value={f.hideNonSuccess} onChange={(v) => update({ hideNonSuccess: v })} />
          <Check label={t("Hide Authentication demands (401, 407)")} value={f.hideAuth} onChange={(v) => update({ hideAuth: v })} />
          <Check label={t("Hide redirects (300, 301, 302, 303, 307)")} value={f.hideRedirects} onChange={(v) => update({ hideRedirects: v })} />
          <Check label={t("Hide Not Modified (304)")} value={f.hideNotModified} onChange={(v) => update({ hideNotModified: v })} />
        </Section>
        <Section title={t("Response Type and Size")}>
          <div className="f-grid2">
            <Check label={t("Hide images")} value={f.hideImages} onChange={(v) => update({ hideImages: v })} />
            <Check label={t("Hide CSS")} value={f.hideCss} onChange={(v) => update({ hideCss: v })} />
            <Check label={t("Hide scripts")} value={f.hideScripts} onChange={(v) => update({ hideScripts: v })} />
            <Check label={t("Hide fonts")} value={f.hideFonts} onChange={(v) => update({ hideFonts: v })} />
          </div>
          <div className="f-row">
            <span>{t("Show only Content-Types")}</span>
            <input value={f.contentTypeShowOnly} placeholder="json; xml" onChange={(e) => update({ contentTypeShowOnly: e.target.value })} />
          </div>
          <div className="f-row">
            <span>{t("Hide Content-Types")}</span>
            <input value={f.contentTypeHide} placeholder="video/; audio/" onChange={(e) => update({ contentTypeHide: e.target.value })} />
          </div>
          <div className="f-row">
            <span>{t("Hide smaller than (KB)")}</span>
            <input type="number" value={f.minSize != null ? f.minSize / 1024 : ""} onChange={(e) => update({ minSize: num(e.target.value) != null ? num(e.target.value)! * 1024 : null })} />
          </div>
          <div className="f-row">
            <span>{t("Hide larger than (KB)")}</span>
            <input type="number" value={f.maxSize != null ? f.maxSize / 1024 : ""} onChange={(e) => update({ maxSize: num(e.target.value) != null ? num(e.target.value)! * 1024 : null })} />
          </div>
          <div className="f-row">
            <span>{t("Hide faster than (ms)")}</span>
            <input type="number" value={f.minDurationMs ?? ""} onChange={(e) => update({ minDurationMs: num(e.target.value) })} />
          </div>
        </Section>
        <Section title={t("Advanced expression")}>
          <textarea
            rows={3}
            className="mono"
            placeholder={'host ~= "*.company.de" and method == POST and status >= 400'}
            value={f.expression}
            onChange={(e) => update({ expression: e.target.value })}
          />
          <div className="muted small">
            {t("Fields")}: host url path method status type process size reqsize time comment protocol color kind client custom via certdays llm tokens · {t("Operators")}: == != ~= ({t("wildcard")}) ~ ({t("contains")}) !~ =~ (regex) &lt; &lt;= &gt; &gt;= · and or not ( ) · status == 4xx · size &gt; 10k · time &gt; 1s
          </div>
        </Section>
      </fieldset>
    </div>
  );
}
