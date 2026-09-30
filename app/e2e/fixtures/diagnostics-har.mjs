// A synthetic capture with typical problems for the diagnostics e2e test (generated at test
// time, so large bodies don't bloat the repository): N+1 OData queries, duplicate and
// semantically duplicate requests, polling, an authentication loop, a redirect chain,
// retried failing saves, a slow report, a large uncompressed response, uncacheable scripts
// and an insecure cookie.
const T0 = Date.parse("2026-09-29T10:00:00.000Z");

function entry(ms, method, url, { status = 200, time = 40, wait, mime = "application/json", text = "{}", reqHeaders = [], resHeaders = [], postData } = {}) {
  const w = wait ?? Math.round(time * 0.8);
  return {
    startedDateTime: new Date(T0 + ms).toISOString(),
    time,
    request: {
      method,
      url,
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: [{ name: "Accept-Encoding", value: "gzip, br" }, { name: "User-Agent", value: "quena-e2e" }, ...reqHeaders],
      queryString: [],
      headersSize: -1,
      bodySize: postData ? postData.length : 0,
      ...(postData ? { postData: { mimeType: "application/json", text: postData } } : {}),
    },
    response: {
      status,
      statusText: "",
      httpVersion: "HTTP/1.1",
      cookies: [],
      headers: [{ name: "Content-Type", value: mime }, ...resHeaders],
      content: { size: text.length, mimeType: mime, text },
      redirectURL: "",
      headersSize: -1,
      bodySize: text.length,
    },
    cache: {},
    timings: { blocked: -1, dns: -1, connect: -1, ssl: -1, send: 1, wait: w, receive: Math.max(0, time - w - 1) },
  };
}

export function diagnosticsHar() {
  const e = [];
  const json = (n) => JSON.stringify({ items: Array.from({ length: n }, (_, i) => ({ id: i, name: `Item ${i}`, text: "lorem ipsum dolor sit amet ".repeat(4) })) });
  // "Open case" at 0 s
  e.push(entry(0, "GET", "https://app.test/case/42", { mime: "text/html", text: "<html><body>case</body></html>", time: 60 }));
  e.push(entry(70, "GET", "https://app.test/static/app.js", { mime: "application/javascript", text: "console.log(1);".repeat(20000), time: 120 }));
  let t = 200;
  for (let i = 0; i < 30; i++, t += 45) e.push(entry(t, "GET", `https://app.test/odata/Documents?$filter=Id eq ${1000 + i}`, { text: json(2), time: 40 }));
  for (let i = 0; i < 8; i++, t += 30) e.push(entry(t, "GET", "https://app.test/api/permissions", { text: '{"read":true}', time: 25 }));
  e.push(entry(t, "GET", "https://app.test/odata/Users?$select=Id,Name&$top=50", { text: json(5), time: 30 }));
  e.push(entry((t += 40), "GET", "https://app.test/odata/Users?$top=50&$select=Name,%20Id", { text: json(5), time: 30 }));
  e.push(entry((t += 40), "GET", "https://app.test/odata/Items", { text: json(9000), time: 900, wait: 200 }));
  e.push(entry((t += 950), "GET", "https://app.test/api/report", { text: "{}", time: 3200, wait: 3100 }));
  // Redirect chain at 8 s
  e.push(entry(8000, "GET", "http://app.test/start", { status: 301, text: "", mime: "text/html", resHeaders: [{ name: "Location", value: "https://app.test/start" }], time: 10 }));
  e.push(entry(8020, "GET", "https://app.test/start", { status: 302, text: "", mime: "text/html", resHeaders: [{ name: "Location", value: "/login" }], time: 10 }));
  e.push(entry(8040, "GET", "https://app.test/login", { status: 302, text: "", mime: "text/html", resHeaders: [{ name: "Location", value: "https://app.test/home" }, { name: "Set-Cookie", value: "session=abc123; Path=/; SameSite=None" }], time: 10 }));
  e.push(entry(8060, "GET", "https://app.test/home", { mime: "text/html", text: "<html>home</html>", time: 20 }));
  // Polling from 10 s: every 2 s, unchanged
  for (let i = 0; i < 12; i++) e.push(entry(10000 + i * 2000, "GET", "https://app.test/api/notifications", { text: '{"count":0}', time: 15 }));
  // Authentication loop at 12 s: never succeeds
  for (let i = 0; i < 4; i++)
    e.push(entry(12000 + i * 300, "GET", "https://legacy.test/api/data", { status: 401, text: "", mime: "text/html", resHeaders: [{ name: "WWW-Authenticate", value: "Negotiate" }], reqHeaders: i ? [{ name: "Authorization", value: "Negotiate YIIGhgYGKwYBBQUCoIIGejCCBnagMDAu" }] : [], time: 20 }));
  // Failing save, retried, at 14 s
  for (let i = 0; i < 3; i++) e.push(entry(14000 + i * 500, "POST", "https://app.test/api/save", { status: 503, text: '{"error":"busy"}', postData: '{"id":42,"title":"x"}', time: 30 }));
  e.push(entry(15600, "POST", "https://app.test/api/save", { postData: '{"id":42,"title":"x"}', time: 60 }));
  return { log: { version: "1.2", creator: { name: "quena-e2e", version: "1" }, entries: e } };
}
