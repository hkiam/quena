import { useEffect, useState } from "react";
import { perf } from "../lib/perf";
import { useStore } from "../store";

export function PerfOverlay() {
  const [s, setS] = useState(perf.summary());
  const total = useStore((x) => x.listTotal);
  const version = useStore((x) => x.listVersion);
  useEffect(() => {
    perf.start();
    const t = setInterval(() => setS(perf.summary()), 500);
    return () => {
      clearInterval(t);
      perf.stop();
    };
  }, []);
  const bad = (v: number, lim: number) => (v > lim ? "bad" : "");
  return (
    <div className="perf-overlay">
      <div>
        <b>{s.fps.toFixed(0)}</b> fps · frame p50 {s.frameP50.toFixed(1)} / <span className={bad(s.frameP99, 16.7)}>p99 {s.frameP99.toFixed(1)} ms</span>
      </div>
      <div>
        IPC p50 {s.ipcP50.toFixed(1)} / <span className={bad(s.ipcP99, 100)}>p99 {s.ipcP99.toFixed(1)} ms</span> · long frames {s.longFrames}
      </div>
      <div>
        long tasks <span className={bad(s.longTasks, 0.5)}>{s.longTasks}</span>
        {s.maxTaskMs > 0 && <> · max <span className={bad(s.maxTaskMs, 50)}>{s.maxTaskMs.toFixed(0)} ms</span></>}
      </div>
      <div>
        rows {total} · v{version}
      </div>
      {s.lastIpc.map((i, k) => (
        <div key={k} className="perf-ipc">
          {i.cmd} {i.ms.toFixed(1)} ms
        </div>
      ))}
    </div>
  );
}
