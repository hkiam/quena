// Lightweight performance probes for the dev overlay and budget checks
// (PLAN.md §2.13.1): frame time, IPC latency, long frames.

type Sample = { t: number; v: number };

class Perf {
  frames: Sample[] = [];
  ipcs: { t: number; cmd: string; ms: number }[] = [];
  longFrames = 0;
  private last = 0;
  private running = false;

  start() {
    if (this.running) return;
    this.running = true;
    const loop = (t: number) => {
      if (this.last) {
        const dt = t - this.last;
        this.frames.push({ t, v: dt });
        if (dt > 50) this.longFrames++;
        if (this.frames.length > 240) this.frames.shift();
      }
      this.last = t;
      if (this.running) requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  stop() {
    this.running = false;
    this.last = 0;
  }

  ipc(cmd: string, ms: number) {
    this.ipcs.push({ t: performance.now(), cmd, ms });
    if (this.ipcs.length > 400) this.ipcs.shift();
  }

  summary() {
    const f = this.frames.map((s) => s.v).sort((a, b) => a - b);
    const q = (arr: number[], p: number) => (arr.length ? arr[Math.min(arr.length - 1, Math.floor(arr.length * p))] : 0);
    const ip = this.ipcs.map((s) => s.ms).sort((a, b) => a - b);
    return {
      fps: f.length ? 1000 / (f.reduce((a, b) => a + b, 0) / f.length) : 0,
      frameP50: q(f, 0.5),
      frameP99: q(f, 0.99),
      ipcP50: q(ip, 0.5),
      ipcP99: q(ip, 0.99),
      longFrames: this.longFrames,
      lastIpc: this.ipcs.slice(-6).reverse(),
    };
  }
}

export const perf = new Perf();
