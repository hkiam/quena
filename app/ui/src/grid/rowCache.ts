// Page cache for viewport rows. The core owns the list; we only keep the
// pages around the viewport (R1). Pages are refetched when the list version
// moves on; stale data stays visible until fresh data arrives (no flicker).
import { api, type RowGroup, type SessionSummary } from "../api";

export const PAGE = 64;
const MAX_PAGES = 64;

interface Page {
  version: number;
  rows: SessionSummary[];
  groups?: (RowGroup | null)[];
  used: number;
}

export class RowCache {
  private pages = new Map<number, Page>();
  private inflight = new Map<number, number>(); // page -> version requested
  version = 0;
  total = 0;
  onUpdate: () => void = () => {};
  private tick = 0;

  invalidate(version: number, total: number) {
    this.version = version;
    this.total = total;
  }

  clear() {
    this.pages.clear();
    this.inflight.clear();
  }

  get(index: number): SessionSummary | undefined {
    const p = this.pages.get(Math.floor(index / PAGE));
    if (!p) return undefined;
    p.used = ++this.tick;
    return p.rows[index % PAGE];
  }

  /** The row's group while the list is grouped. */
  group(index: number): RowGroup | null {
    const p = this.pages.get(Math.floor(index / PAGE));
    return p?.groups?.[index % PAGE] ?? null;
  }

  isFresh(index: number): boolean {
    const p = this.pages.get(Math.floor(index / PAGE));
    return !!p && p.version >= this.version;
  }

  /** Make sure rows [first, last] are (being) loaded at the current version. */
  ensure(first: number, last: number) {
    if (this.total === 0) return;
    const a = Math.max(0, Math.floor(first / PAGE));
    const b = Math.min(Math.floor((this.total - 1) / PAGE), Math.floor(last / PAGE));
    for (let p = a; p <= b; p++) {
      const page = this.pages.get(p);
      if (page && page.version >= this.version) continue;
      const req = this.inflight.get(p);
      if (req !== undefined && req >= this.version) continue;
      this.fetch(p);
    }
  }

  private async fetch(p: number) {
    const v = this.version;
    this.inflight.set(p, v);
    try {
      const w = await api.rows(p * PAGE, PAGE);
      const cur = this.pages.get(p);
      if (!cur || cur.version <= w.version) {
        this.pages.set(p, { version: w.version, rows: w.rows, groups: w.groups, used: ++this.tick });
      }
      if (w.version > this.version) this.version = w.version;
      this.total = w.total;
      this.evict();
      this.onUpdate();
    } catch (e) {
      console.warn("rows", e);
    } finally {
      if (this.inflight.get(p) === v) this.inflight.delete(p);
    }
  }

  private evict() {
    if (this.pages.size <= MAX_PAGES) return;
    const entries = [...this.pages.entries()].sort((x, y) => x[1].used - y[1].used);
    for (const [k] of entries.slice(0, this.pages.size - MAX_PAGES)) this.pages.delete(k);
  }

  /** Ids for a range if all rows are cached, else null. */
  idsIfCached(first: number, last: number): number[] | null {
    const out: number[] = [];
    for (let i = first; i <= last; i++) {
      const r = this.get(i);
      if (!r) return null;
      out.push(r.id);
    }
    return out;
  }
}
