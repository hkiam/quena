// Minimal W3C WebDriver client (no dependencies) for driving the real Quena app through
// tauri-driver. Only what the end-to-end tests need.
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";

export class Driver {
  constructor(base = "http://127.0.0.1:4444") {
    this.base = base;
    this.id = null;
  }

  async cmd(method, path, body) {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || json.value?.error) {
      const e = json.value ?? {};
      throw new Error(`${method} ${path}: ${e.error ?? res.status} ${e.message ?? ""}`.trim());
    }
    return json.value;
  }

  s(path) {
    return `/session/${this.id}${path}`;
  }

  async start(application, args = []) {
    // On Windows the Edge WebDriver hands `args` to the WebView2 browser engine, not to the
    // app, so archives are loaded through the app's test hook instead of argv.
    const viaHook = process.platform === "win32";
    const v = await this.cmd("POST", "/session", {
      capabilities: { alwaysMatch: { browserName: "wry", "tauri:options": { application, args: viaHook ? [] : args } } },
    });
    this.id = v.sessionId;
    if (viaHook && args.length) {
      const end = Date.now() + 20000;
      while (!(await this.exec("return !!(window.__quena && window.__quena.load)").catch(() => false))) {
        if (Date.now() > end) throw new Error("the app's test hook did not appear");
        await new Promise((r) => setTimeout(r, 200));
      }
      for (const a of args) await this.exec("return window.__quena.load(arguments[0]).then(() => true)", [a]);
    }
  }

  /** Switch capturing on if it is paused: an archive passed at start is an import, and
   *  imports stop capturing (on Windows archives are loaded through the test hook instead). */
  async ensureCapturing() {
    const sw = await this.waitFor(".capture-switch");
    if ((await this.text(sw)).includes("Capturing")) return;
    await this.click(sw);
    await this.waitFor(".capture-switch", { text: "Capturing" });
  }

  async quit() {
    if (this.id) await this.cmd("DELETE", `/session/${this.id}`).catch(() => {});
    this.id = null;
  }

  async findAll(css) {
    const list = await this.cmd("POST", this.s("/elements"), { using: "css selector", value: css });
    return list.map((e) => e[ELEMENT]);
  }

  async findIn(el, css) {
    const list = await this.cmd("POST", this.s(`/element/${el}/elements`), { using: "css selector", value: css });
    return list.map((e) => e[ELEMENT]);
  }

  /** Wait until `css` matches (and, if given, `pred(text)` holds); returns the element id. */
  async waitFor(css, { timeout = 10000, text } = {}) {
    const end = Date.now() + timeout;
    let last = "";
    for (;;) {
      for (const el of await this.findAll(css).catch(() => [])) {
        last = await this.text(el).catch(() => "");
        if (!text || (typeof text === "function" ? text(last) : last.includes(text))) return el;
      }
      if (Date.now() > end) throw new Error(`timeout waiting for ${css}${text ? ` with text ${text}` : ""} (last: ${JSON.stringify(last).slice(0, 200)})`);
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  /** Text content (DOM), independent of CSS visibility, clipping or ellipsis. */
  text(el) {
    return this.exec("return arguments[0].textContent", [{ [ELEMENT]: el }]);
  }

  click(el) {
    return this.cmd("POST", this.s(`/element/${el}/click`), {});
  }

  type(el, text) {
    return this.cmd("POST", this.s(`/element/${el}/value`), { text });
  }

  exec(script, args = []) {
    return this.cmd("POST", this.s("/execute/sync"), { script, args });
  }

  rect(el) {
    return this.cmd("GET", this.s(`/element/${el}/rect`));
  }

  /** Click at (x, y) from the element's top-left corner (e.g. a row of the canvas list);
   * `button` 2 is a right-click. */
  async clickAt(el, x, y, button = 0) {
    // WebDriver measures element-relative pointer offsets from the element's centre.
    const r = await this.rect(el);
    x = Math.round(x - r.width / 2);
    y = Math.round(y - r.height / 2);
    await this.cmd("POST", this.s("/actions"), {
      actions: [
        {
          type: "pointer",
          id: "mouse",
          parameters: { pointerType: "mouse" },
          actions: [
            { type: "pointerMove", origin: { [ELEMENT]: el }, x, y },
            { type: "pointerDown", button },
            { type: "pointerUp", button },
          ],
        },
      ],
    });
    // WebKitWebDriver keeps the right button pressed after its pointerUp (later events carry
    // buttons: 2, and a left press is then a chord without pointerdown, so drags never start):
    // release it once more, then the input state.
    if (button !== 0) {
      await this.cmd("POST", this.s("/actions"), {
        actions: [{ type: "pointer", id: "mouse", parameters: { pointerType: "mouse" }, actions: [{ type: "pointerUp", button }] }],
      });
    }
    await this.cmd("DELETE", this.s("/actions"));
  }

  /** Press a key chord, e.g. keys(["Control", "f"]). */
  keys(chord) {
    const map = { Control: "", Shift: "", Alt: "", Escape: "", Enter: "", Backspace: "", Delete: "" };
    const k = chord.map((c) => map[c] ?? c);
    return this.cmd("POST", this.s("/actions"), {
      actions: [{ type: "key", id: "kbd", actions: [...k.map((value) => ({ type: "keyDown", value })), ...k.reverse().map((value) => ({ type: "keyUp", value }))] }],
    });
  }
}
