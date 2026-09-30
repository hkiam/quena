import { describe, expect, it } from "vitest";
import type { Detail } from "../api";
import { buildCurl, buildFetch, buildPowerShell, buildPython } from "./http";

const detail = (body = 0) =>
  ({
    summary: { id: 7 },
    request: {
      method: "POST",
      url: "https://api.example.com/v1/items?x=1",
      version: "HTTP/1.1",
      headers: [
        ["Host", "api.example.com"],
        ["Content-Type", "application/json"],
        ["User-Agent", "quena-test"],
        ["X-It's", "o'clock"],
        ["Content-Length", "13"],
      ],
    },
    requestBody: { len: body, isText: true },
  }) as unknown as Detail;

describe("copy as …", () => {
  it("fetch: method, headers without hop-by-hop ones, body", () => {
    const s = buildFetch(detail(13), '{"a":"b\'c"}');
    expect(s).toContain('await fetch("https://api.example.com/v1/items?x=1"');
    expect(s).toContain('"Content-Type": "application/json"');
    expect(s).not.toContain("Content-Length");
    expect(s).not.toContain('"Host"');
    expect(s).toContain(`body: ${JSON.stringify('{"a":"b\'c"}')}`);
  });
  it("PowerShell: content type and user agent as parameters, quotes escaped", () => {
    const s = buildPowerShell(detail(13), "{}");
    expect(s).toContain("-Method POST");
    expect(s).toContain("-ContentType 'application/json'");
    expect(s).toContain("-UserAgent 'quena-test'");
    expect(s).toContain("'X-It''s' = 'o''clock'");
    expect(s).not.toMatch(/Content-Type' =/);
  });
  it("Python: requests call with headers and data", () => {
    const s = buildPython(detail(13), "{}");
    expect(s).toContain("requests.request(");
    expect(s).toContain('"POST",');
    expect(s).toContain('"User-Agent": "quena-test",');
    expect(s).toContain('data="{}".encode("utf-8"),');
  });
  it("binary or large bodies are referenced, not inlined", () => {
    expect(buildPython(detail(5_000_000), null)).toContain('open("body-7.bin", "rb")');
    expect(buildPowerShell(detail(5_000_000), null)).toContain("-InFile 'body-7.bin'");
    expect(buildFetch(detail(5_000_000), null)).toContain("5000000 bytes");
    expect(buildCurl(detail(5_000_000), null)).toContain("@body-7.bin");
  });
});

// ---- hostile input: nothing may leave its string literal ----

type Hdr = [string, string];
const hostile = (method: string, headers: Hdr[], body = 0, url = "https://h.example/p?q=1") =>
  ({
    summary: { id: 9 },
    request: { method, url, version: "HTTP/1.1", headers },
    requestBody: { len: body, isText: true },
  }) as unknown as Detail;

const EVIL = "a'b’c‘d‚e‛f $(id) `id` | & ; \" $x !! \n next line ü € 😀";
const EVIL_HEADERS: Hdr[] = [
  ["X-Evil", EVIL],
  ["Cookie", "a=1"],
  ["accept", "text/html"],
  ["cookie", "b=2"],
  ["Accept", "application/json"],
];
const METHODS = ["GET|calc", "GET$(id)", "X`id`", "A'B", "A’B", "A&B", "A;B"];

/** Node's child_process, loaded without typing the whole module (the UI has no @types/node). */
type Spawn = (cmd: string, args: string[], o: { input?: string; encoding: "utf8" }) => { status: number | null; stdout: string; stderr: string; error?: unknown };
async function spawner(): Promise<Spawn | null> {
  try {
    const mod = "node:child_process";
    return ((await import(/* @vite-ignore */ mod)) as { spawnSync: Spawn }).spawnSync;
  } catch {
    return null;
  }
}
/** Base64 of UTF-16LE, the encoding `pwsh -EncodedCommand` expects. */
const utf16b64 = (s: string) => btoa(Array.from({ length: s.length }, (_, i) => s.charCodeAt(i)).map((c) => String.fromCharCode(c & 0xff, c >> 8)).join(""));
const has = (spawn: Spawn | null, cmd: string, args: string[]) => !!spawn && !spawn(cmd, args, { encoding: "utf8" }).error;

describe("copy as … with hostile input", () => {
  it("curl: method and every value are single-quoted", () => {
    for (const m of METHODS) {
      const s = buildCurl(hostile(m, []), null);
      expect(s).toContain(`-X '${m.replace(/'/g, `'\\''`)}'`);
    }
    const s = buildCurl(hostile("POST", EVIL_HEADERS), EVIL);
    expect(s).toContain(`-H 'X-Evil: a'\\''b’c‘d‚e‛f $(id) \`id\``);
    expect(s).toContain(`--data-binary 'a'\\''b`);
  });
  it("curl: control characters are ANSI-C escaped; NUL bodies go to the file; leading dash URL uses --url", () => {
    expect(buildCurl(hostile("POST", [["X-A", "a\x1bb\rc"]]), null)).toContain(`'X-A: a'$'\\x1b''b'$'\\x0d''c'`);
    const nul = buildCurl(hostile("POST", []), "a\0b");
    expect(nul).toContain("--data-binary '@body-9.bin'");
    expect(nul).not.toContain("a\0b");
    expect(buildCurl(hostile("GET", [], 0, "-o/tmp/x"), null)).toContain("--url '-o/tmp/x'");
  });
  it("PowerShell: nonstandard methods only via -CustomMethod, quoted", () => {
    for (const m of METHODS) {
      const s = buildPowerShell(hostile(m, []), null);
      expect(s).not.toContain("-Method ");
      expect(s).toContain(`-CustomMethod '${m.replace(/['’]/g, "$&$&")}'`);
    }
    expect(buildPowerShell(hostile("patch", []), null)).toContain("-Method PATCH");
  });
  it("PowerShell: all single-quote variants are doubled", () => {
    const s = buildPowerShell(hostile("POST", EVIL_HEADERS), EVIL);
    expect(s).toContain("'X-Evil' = 'a''b’’c‘‘d‚‚e‛‛f $(id) `id` | & ; \" $x !! \n next line ü € 😀'");
    expect(s).toContain("-Body 'a''b’’c‘‘d‚‚e‛‛f");
  });
  it("PowerShell: duplicate headers are merged case-insensitively", () => {
    const s = buildPowerShell(hostile("GET", EVIL_HEADERS), null);
    expect(s).toContain("'Cookie' = 'a=1; b=2'");
    expect(s).toContain("'accept' = 'text/html, application/json'");
    expect(s.match(/'cookie'/gi)).toHaveLength(1);
  });
  it("PowerShell: control characters are spliced in as [char]", () => {
    expect(buildPowerShell(hostile("POST", []), "a\0b\x1b")).toContain("-Body ('a' + [char]0 + 'b' + [char]27)");
  });
  it("fetch / Python: method and values are JSON literals; duplicates merged", () => {
    for (const m of METHODS) {
      expect(buildFetch(hostile(m, []), null)).toContain(`method: ${JSON.stringify(m)},`);
      expect(buildPython(hostile(m, []), null)).toContain(`    ${JSON.stringify(m)},`);
    }
    for (const s of [buildFetch(hostile("POST", EVIL_HEADERS), EVIL), buildPython(hostile("POST", EVIL_HEADERS), EVIL)]) {
      expect(s).toContain(`"X-Evil": ${JSON.stringify(EVIL)},`);
      expect(s).toContain(`"Cookie": "a=1; b=2",`);
      expect(s).toContain(`"accept": "text/html, application/json",`);
      expect(s).toContain(JSON.stringify(EVIL));
    }
  });

  // Optional round trips through a real shell: skipped when bash / pwsh are not installed.
  it("curl: bash hands curl exactly the original arguments", async () => {
    const spawn = await spawner();
    if (!has(spawn, "bash", ["-c", "true"])) return;
    for (const m of METHODS) {
      const d = hostile(m, [["X-Evil", EVIL], ["X-Ctl", "a\x1bb\rc"]]);
      const script = `curl() { printf '%s\\0' "$@"; }\n${buildCurl(d, EVIL)}\n`;
      const r = spawn!("bash", ["--noprofile", "--norc", "-s"], { input: script, encoding: "utf8" });
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout.split("\0").slice(0, -1)).toEqual(["-X", m, d.request.url, "-H", `X-Evil: ${EVIL}`, "-H", "X-Ctl: a\x1bb\rc", "--data-binary", EVIL]);
    }
  });
  it("PowerShell: pwsh parses the script and binds the original values", async () => {
    const spawn = await spawner();
    if (!has(spawn, "pwsh", ["-NoProfile", "-NonInteractive", "-Command", "exit 0"])) return;
    // The fake below mirrors the real cmdlet's parameter names.
    const names = spawn!("pwsh", ["-NoProfile", "-NonInteractive", "-Command", "(Get-Command Invoke-WebRequest).Parameters.Keys -join ','"], { encoding: "utf8" });
    expect(names.stdout.trim().split(",")).toEqual(expect.arrayContaining(["Uri", "Method", "CustomMethod", "Headers", "ContentType", "UserAgent", "Body", "InFile"]));
    for (const m of [...METHODS, "POST"]) {
      const d = hostile(m, [...EVIL_HEADERS, ["Content-Type", "text/plain"]]);
      const body = EVIL + "\0\x1b";
      const fake =
        "function Invoke-WebRequest { param($Uri, $Method, $CustomMethod, $Headers, $ContentType, $UserAgent, $Body, $InFile)\n" +
        "  $h = [ordered]@{}; foreach ($k in ($Headers.Keys | Sort-Object)) { $h[$k] = $Headers[$k] }\n" +
        "  [Console]::Out.Write((@{ Uri = $Uri; Method = \"$Method\"; CustomMethod = $CustomMethod; Headers = $h; ContentType = $ContentType; Body = $Body } | ConvertTo-Json -Compress -Depth 3)) }\n";
      const r = spawn!("pwsh", ["-NoProfile", "-NonInteractive", "-EncodedCommand", utf16b64(fake + buildPowerShell(d, body))], { encoding: "utf8" });
      expect(r.status, r.stderr).toBe(0);
      const got = JSON.parse(r.stdout.trim());
      expect(got.Uri).toBe(d.request.url);
      if (m === "POST") expect(got.Method).toBe("POST");
      else expect(got.CustomMethod).toBe(m);
      expect(got.Body).toBe(body);
      expect(got.ContentType).toBe("text/plain");
      expect(got.Headers["X-Evil"]).toBe(EVIL);
      expect(got.Headers.Cookie).toBe("a=1; b=2");
    }
  }, 60_000);
});
