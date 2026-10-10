// Tools and skills across the agent runs of the capture: what each tool definition costs in
// every request, how often the model calls it, what the MCP server answers; which skills are
// offered and which loaded.
import { useEffect, useState } from "react";
import { api, type ToolReport } from "../api";
import { fmtInt } from "../lib/format";
import { t } from "../i18n";

export function AgentTools({ refresh }: { refresh: string }) {
  const [r, setR] = useState<ToolReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [onlyUnused, setOnlyUnused] = useState(false);
  useEffect(() => {
    let alive = true;
    api.toolReport().then(
      (x) => alive && (setR(x), setError(null)),
      (e) => alive && setError(String(e)),
    );
    return () => {
      alive = false;
    };
  }, [refresh]);
  if (!r) return <div className="placeholder">{error ?? t("Computing…")}</div>;
  if (!r.tools.length && !r.skills.length) return <div className="placeholder">{t("No tools in the LLM calls or MCP exchanges of the capture.")}</div>;
  const tools = onlyUnused ? r.tools.filter((x) => x.offered > 0 && x.modelCalls === 0) : r.tools;
  const unusedTokens = r.tools.filter((x) => x.offered > 0 && x.modelCalls === 0).reduce((a, x) => a + x.defTokens * x.offered, 0);
  return (
    <div className="scroll pad agent-tools">
      {error && <div className="mocks-error small">{error}</div>}
      <div className="conv-facts small">
        <span>{t("{n} LLM requests", { n: fmtInt(r.requests) })}</span>
        <span>{t("{n} tools", { n: r.tools.length })}</span>
        {unusedTokens > 0 && <span className="warn">{t("tools never called cost {n} tokens in all", { n: fmtInt(unusedTokens) })}</span>}
        <span className="tp-spacer" />
        <label className="f-check">
          <input type="checkbox" checked={onlyUnused} onChange={(e) => setOnlyUnused(e.target.checked)} /> {t("Only tools never called")}
        </label>
      </div>
      <table className="agt-table">
        <thead>
          <tr>
            <th>{t("Tool")}</th>
            <th>{t("Server")}</th>
            <th className="num" title={t("LLM requests that offer the tool")}>
              {t("Offered")}
            </th>
            <th className="num" title={t("Tokens of its definition in each request that offers it")}>
              {t("Definition")}
            </th>
            <th className="num" title={t("Definition tokens × requests")}>
              {t("Cost in all")}
            </th>
            <th className="num" title={t("Calls the model asked for")}>
              {t("Called")}
            </th>
            <th className="num" title={t("Exchanges with the MCP server")}>
              MCP
            </th>
            <th className="num">{t("Errors")}</th>
            <th className="num" title={t("Average and largest result, in tokens")}>
              {t("Result")}
            </th>
          </tr>
        </thead>
        <tbody>
          {tools.map((x) => (
            <tr key={x.name} className={x.offered > 0 && x.modelCalls === 0 && x.mcpCalls === 0 ? "side" : ""}>
              <td className="mono" title={x.name}>
                {x.name}
              </td>
              <td className="small">{x.server ?? ""}</td>
              <td className="num">{x.offered || ""}</td>
              <td className="num">{x.defTokens ? fmtInt(x.defTokens) : ""}</td>
              <td className="num">{x.offered ? fmtInt(x.defTokens * x.offered) : ""}</td>
              <td className="num">{x.modelCalls || ""}</td>
              <td className="num">{x.mcpCalls || ""}</td>
              <td className={`num ${x.errors ? "warn" : ""}`}>{x.errors || ""}</td>
              <td className="num">{x.mcpCalls ? `${fmtInt(Math.round(x.resultTokens / x.mcpCalls))} / ${fmtInt(x.maxResultTokens)}` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {r.skills.length > 0 && (
        <>
          <h4>{t("Skills")}</h4>
          <table className="agt-table">
            <thead>
              <tr>
                <th>{t("Skill")}</th>
                <th className="num" title={t("Conversations whose requests list the skill")}>
                  {t("Offered")}
                </th>
                <th className="num" title={t("Times the model loaded it (Skill tool or reading SKILL.md)")}>
                  {t("Loaded")}
                </th>
                <th className="num">{t("Conversations")}</th>
              </tr>
            </thead>
            <tbody>
              {r.skills.map((s) => (
                <tr key={s.name} className={s.used === 0 ? "side" : ""}>
                  <td className="mono">{s.name}</td>
                  <td className="num">{s.offered || ""}</td>
                  <td className="num">{s.used || ""}</td>
                  <td className="num">{s.convsUsed || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
