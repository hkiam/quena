import { describe, expect, it } from "vitest";
import { phasesOf } from "./waterfall";

const T0 = 1_700_000_000_000_000;
const ms = (n: number) => T0 + n * 1000;

describe("waterfall phases", () => {
  it("splits a fresh connection into DNS, connect and TLS", () => {
    const p = phasesOf({
      clientBeginRequest: ms(0),
      clientDoneRequest: ms(2),
      serverConnectStart: ms(2),
      serverConnected: ms(62),
      dnsMs: 10,
      tcpConnectMs: 20,
      tlsHandshakeMs: 30,
      serverBeginRequest: ms(62),
      serverDoneRequest: ms(63),
      serverGotFirstByte: ms(163),
      serverDoneResponse: ms(200),
    });
    expect(p.map((s) => [s.phase, (s.end - s.start) / 1000])).toEqual([
      ["request", 2],
      ["dns", 10],
      ["connect", 20],
      ["tls", 30],
      ["send", 1],
      ["wait", 100],
      ["receive", 37],
    ]);
  });
  it("leaves out missing and inconsistent timers and never overlaps", () => {
    const p = phasesOf({ clientBeginRequest: ms(0), clientDoneRequest: ms(5), serverBeginRequest: ms(3), serverGotFirstByte: ms(1), serverDoneResponse: ms(9) });
    expect(p.map((s) => s.phase)).toEqual(["request", "receive"]);
    for (let i = 1; i < p.length; i++) expect(p[i].start).toBeGreaterThanOrEqual(p[i - 1].end);
    expect(phasesOf({})).toEqual([]);
  });
});
