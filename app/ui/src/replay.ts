import { say } from "./store";

export interface ReplayOptions {
  unconditional?: boolean;
  repeat?: boolean;
  breakpoint?: boolean;
}

export async function replaySelected(_o: ReplayOptions) {
  say("Replay requires the capture engine (milestone M4)", "error");
}

export async function toComposer() {
  say("Composer arrives with milestone M4", "error");
}
