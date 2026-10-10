import { useEffect, useRef, useState } from "react";
import { useStore } from "../store";
import { api } from "../api";

/** `value` once it has not changed for `quiet` ms, and at least every `most` ms while it keeps
 * changing (an agent at work changes the list all the time). */
export function useSettled<T>(value: T, quiet = 400, most = 3000): T {
  const [settled, setSettled] = useState(value);
  const since = useRef(Date.now());
  useEffect(() => {
    if (Object.is(value, settled)) return;
    const wait = Math.max(0, Math.min(quiet, most - (Date.now() - since.current)));
    const timer = setTimeout(() => {
      since.current = Date.now();
      setSettled(value);
    }, wait);
    return () => clearTimeout(timer);
  }, [value, settled, quiet, most]);
  return settled;
}

/** The session list's version, settled: for views that follow new sessions without asking
 * on every change. */
export function useListVersion(): number {
  return useSettled(useStore((s) => s.listVersion));
}

/** Changes only when LLM calls or MCP exchanges were added or marked (asked of the core as
 * the list changes): views of agent data reload then, not on every other session. */
export function useAgentStamp(): number {
  const version = useListVersion();
  const [stamp, setStamp] = useState(0);
  useEffect(() => {
    let alive = true;
    api.agentStamp().then((s) => alive && setStamp(s), () => {});
    return () => {
      alive = false;
    };
  }, [version]);
  return stamp;
}
