import { useRef, useState } from "react";
import { actions } from "../actions";

const HISTORY_KEY = "quena.quickexec.history";

function loadHistory(): string[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export function QuickExec() {
  const [value, setValue] = useState("");
  const history = useRef<string[]>(loadHistory());
  const pos = useRef(-1);

  const run = async () => {
    const v = value.trim();
    if (!v) return;
    const ok = await actions.quickexec(v);
    history.current = [v, ...history.current.filter((h) => h !== v)].slice(0, 100);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history.current));
    } catch {
      /* ignore */
    }
    pos.current = -1;
    if (ok) setValue("");
  };

  return (
    <div className="quickexec">
      <input
        value={value}
        spellCheck={false}
        placeholder="Command: ?text  =404  @host  >10k  bpu /login  cls  help   (Alt+Q)"
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") run();
          else if (e.key === "ArrowUp") {
            const h = history.current;
            if (pos.current < h.length - 1) {
              pos.current++;
              setValue(h[pos.current]);
            }
            e.preventDefault();
          } else if (e.key === "ArrowDown") {
            if (pos.current > 0) {
              pos.current--;
              setValue(history.current[pos.current]);
            } else {
              pos.current = -1;
              setValue("");
            }
            e.preventDefault();
          } else if (e.key === "Escape") {
            setValue("");
            (document.querySelector(".grid-scroller") as HTMLElement | null)?.focus();
          }
        }}
      />
    </div>
  );
}
