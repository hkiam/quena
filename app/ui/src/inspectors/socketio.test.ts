import { describe, expect, it } from "vitest";
import type { Detail, WsFrame } from "../api";
import { isHeartbeat, sioLabel } from "./WebSocketView";
import { socketioCandidate } from "./SocketIoView";

const frame = (o: Partial<WsFrame>): WsFrame => ({ seq: 0, dir: 0, opcode: 1, opcodeName: "text", fin: true, time: 0, len: 1, text: "", preview: null, offset: 0, ...o });

describe("Socket.IO", () => {
  it("labels packets by event, type or Engine.IO type", () => {
    expect(sioLabel({ eio: "message", sio: "event", event: "chat" })).toBe("chat");
    expect(sioLabel({ eio: "message", sio: "ack", ack: 7 })).toBe("ack #7");
    expect(sioLabel({ eio: "ping" })).toBe("ping");
  });
  it("knows heartbeats", () => {
    expect(isHeartbeat(frame({ opcode: 9 }))).toBe(true);
    expect(isHeartbeat(frame({ sio: { eio: "pong" } }))).toBe(true);
    expect(isHeartbeat(frame({ sio: { eio: "message", sio: "event", event: "x" } }))).toBe(false);
  });
  it("recognises polling sessions", () => {
    const d = (url: string, len = 0) => ({ request: { url }, requestBody: { len } }) as unknown as Detail;
    const poll = "https://x.example/socket.io/?EIO=4&transport=polling&t=abc";
    expect(socketioCandidate(d(poll), "response")).toBe(true);
    expect(socketioCandidate(d(poll), "request")).toBe(false);
    expect(socketioCandidate(d(poll, 20), "request")).toBe(true);
    expect(socketioCandidate(d("https://x.example/socket.io/?EIO=4&transport=websocket"), "response")).toBe(false);
    expect(socketioCandidate(d("https://x.example/api"), "response")).toBe(false);
  });
});
