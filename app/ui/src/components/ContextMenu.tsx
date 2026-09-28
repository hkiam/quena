import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { create } from "zustand";

export interface MenuItem {
  label?: string;
  shortcut?: string;
  action?: () => void;
  submenu?: MenuItem[];
  checked?: boolean;
  disabled?: boolean;
  separator?: boolean;
}

interface MenuState {
  open: { x: number; y: number; items: MenuItem[] } | null;
}

const useMenu = create<MenuState>(() => ({ open: null }));

export function showContextMenu(x: number, y: number, items: MenuItem[]) {
  useMenu.setState({ open: { x, y, items } });
}

export function hideContextMenu() {
  useMenu.setState({ open: null });
}

function MenuList({ items, x, y, depth }: { items: MenuItem[]; x: number; y: number; depth: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x, y });
  const [sub, setSub] = useState<{ i: number; x: number; y: number } | null>(null);
  const [hi, setHi] = useState(-1);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    let nx = x;
    let ny = y;
    if (nx + r.width > window.innerWidth - 4) nx = depth ? x - r.width - 190 : window.innerWidth - r.width - 4;
    if (ny + r.height > window.innerHeight - 4) ny = Math.max(4, window.innerHeight - r.height - 4);
    setPos({ x: Math.max(4, nx), y: ny });
  }, [x, y, depth]);

  useEffect(() => {
    if (depth) return;
    const onKey = (e: KeyboardEvent) => {
      const selectable = items.map((it, i) => (!it.separator && !it.disabled ? i : -1)).filter((i) => i >= 0);
      if (e.key === "Escape") hideContextMenu();
      else if (e.key === "ArrowDown") {
        const n = selectable.find((i) => i > hi) ?? selectable[0];
        setHi(n);
      } else if (e.key === "ArrowUp") {
        const n = [...selectable].reverse().find((i) => i < hi) ?? selectable[selectable.length - 1];
        setHi(n);
      } else if (e.key === "Enter" && hi >= 0) {
        const it = items[hi];
        if (it.action) {
          hideContextMenu();
          it.action();
        }
      } else return;
      e.preventDefault();
      e.stopPropagation();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [items, hi, depth]);

  return (
    <div ref={ref} className="ctx-menu" style={{ left: pos.x, top: pos.y }} onMouseDown={(e) => e.stopPropagation()}>
      {items.map((it, i) =>
        it.separator ? (
          <div key={i} className="ctx-sep" />
        ) : (
          <div
            key={i}
            className={`ctx-item ${it.disabled ? "disabled" : ""} ${hi === i ? "hi" : ""}`}
            onMouseEnter={(e) => {
              setHi(i);
              if (it.submenu) {
                const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
                setSub({ i, x: r.right - 2, y: r.top - 4 });
              } else setSub(null);
            }}
            onClick={() => {
              if (it.disabled || it.submenu) return;
              hideContextMenu();
              it.action?.();
            }}
          >
            <span className="ctx-check">{it.checked ? "✓" : ""}</span>
            <span className="ctx-label">{it.label}</span>
            <span className="ctx-shortcut">{it.submenu ? "▸" : it.shortcut}</span>
          </div>
        ),
      )}
      {sub && items[sub.i]?.submenu && <MenuList items={items[sub.i].submenu!} x={sub.x} y={sub.y} depth={depth + 1} />}
    </div>
  );
}

export function ContextMenuHost() {
  const open = useMenu((s) => s.open);
  useEffect(() => {
    if (!open) return;
    const close = () => hideContextMenu();
    window.addEventListener("mousedown", close);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    };
  }, [open]);
  if (!open) return null;
  return <MenuList items={open.items} x={open.x} y={open.y} depth={0} />;
}
