// Quena scripting prelude. Injected before the user script. Defines the
// `console`, the `Headers` helper, the `Session` object handed to hooks, and
// the internal __dispatch* entry points the Rust host calls per session.
;(function (g) {
  function fmt(v) {
    try { return (v !== null && typeof v === 'object') ? JSON.stringify(v) : String(v); }
    catch (e) { return String(v); }
  }
  function log(level) {
    var a = Array.prototype.slice.call(arguments, 1);
    __log(level, a.map(fmt).join(' '));
  }
  g.console = {
    log: function () { log.apply(null, ['log'].concat(Array.prototype.slice.call(arguments))); },
    info: function () { log.apply(null, ['log'].concat(Array.prototype.slice.call(arguments))); },
    warn: function () { log.apply(null, ['warn'].concat(Array.prototype.slice.call(arguments))); },
    error: function () { log.apply(null, ['error'].concat(Array.prototype.slice.call(arguments))); },
    debug: function () { log.apply(null, ['debug'].concat(Array.prototype.slice.call(arguments))); },
  };

  // Ordered, case-insensitive header list. Tracks whether it was modified so
  // the host only rewrites headers the script actually touched.
  function Headers(pairs) {
    this._ = (pairs || []).map(function (p) { return [p[0], p[1]]; });
    this._dirty = false;
  }
  Headers.prototype._find = function (n) {
    n = String(n).toLowerCase();
    for (var i = 0; i < this._.length; i++) if (this._[i][0].toLowerCase() === n) return i;
    return -1;
  };
  Headers.prototype.get = function (n) { var i = this._find(n); return i < 0 ? null : this._[i][1]; };
  Headers.prototype.getAll = function (n) {
    n = String(n).toLowerCase();
    return this._.filter(function (p) { return p[0].toLowerCase() === n; }).map(function (p) { return p[1]; });
  };
  Headers.prototype.has = function (n) { return this._find(n) >= 0; };
  Headers.prototype.set = function (n, v) {
    this._dirty = true;
    var ln = String(n).toLowerCase(), i = this._find(n);
    if (i < 0) { this._.push([String(n), String(v)]); return this; }
    this._[i][1] = String(v);
    this._ = this._.filter(function (p, idx) { return idx === i || p[0].toLowerCase() !== ln; });
    return this;
  };
  Headers.prototype.add = function (n, v) { this._dirty = true; this._.push([String(n), String(v)]); return this; };
  Headers.prototype.remove = function (n) {
    this._dirty = true;
    var ln = String(n).toLowerCase();
    this._ = this._.filter(function (p) { return p[0].toLowerCase() !== ln; });
    return this;
  };
  Headers.prototype.names = function () { return this._.map(function (p) { return p[0]; }); };
  Headers.prototype.toArray = function () { return this._.map(function (p) { return [p[0], p[1]]; }); };
  g.Headers = Headers;

  // Script extensibility: custom menu commands and a custom column.
  g.Quena = {
    _menus: [],
    _column: null,
    registerMenu: function (label, handler) {
      if (typeof handler === 'function') g.Quena._menus.push({ label: String(label), handler: handler });
    },
    registerColumn: function (title, fn) {
      g.Quena._column = { title: String(title), fn: typeof fn === 'function' ? fn : null };
    },
    log: function () { log.apply(null, ['log'].concat(Array.prototype.slice.call(arguments))); },
  };

  function Session(raw, phase) {
    this.id = raw.id; this.process = raw.process || ''; this.clientIp = raw.clientIp || '';
    this.phase = phase;
    this.url = raw.url;
    if (phase === 'request') {
      this.method = raw.method; this.host = raw.host; this.path = raw.path;
      this.requestHeaders = new Headers(raw.headers);
    } else {
      this.status = raw.status; this.reason = raw.reason;
      this.responseHeaders = new Headers(raw.headers);
    }
    this._comment = null; this._color = null; this._custom = null; this._flags = [];
    this._action = 'continue';
    this._respStatus = 200; this._respHeaders = []; this._respBody = '';
  }
  Session.prototype.comment = function (t) { this._comment = String(t); return this; };
  Session.prototype.custom = function (v) { this._custom = v == null ? null : String(v); return this; };
  Session.prototype.color = function (c) { this._color = String(c); return this; };
  Session.prototype.flag = function (k, v) { this._flags.push([String(k), String(v)]); return this; };
  Session.prototype.abort = function () { this._action = 'abort'; };
  Session.prototype.redirect = function (url) { this.url = String(url); };
  Session.prototype.respond = function (status, body, headers) {
    this._action = 'respond';
    this._respStatus = status | 0;
    this._respBody = body == null ? '' : String(body);
    this._respHeaders = [];
    if (headers) for (var k in headers) if (Object.prototype.hasOwnProperty.call(headers, k)) this._respHeaders.push([k, String(headers[k])]);
  };

  function meta(s, out) { out.comment = s._comment; out.color = s._color; out.custom = s._custom; out.flags = s._flags; }

  g.__dispatchRequest = function (json) {
    var raw = JSON.parse(json), s = new Session(raw, 'request'), out = { action: 'continue' };
    if (typeof g.onBeforeRequest === 'function') g.onBeforeRequest(s);
    out.action = s._action; meta(s, out);
    if (s._action === 'respond') { out.status = s._respStatus; out.respHeaders = s._respHeaders; out.respBody = s._respBody; }
    else if (s._action === 'continue') {
      out.method = s.method; out.url = s.url;
      out.headers = s.requestHeaders._dirty ? s.requestHeaders.toArray() : null;
    }
    return JSON.stringify(out);
  };

  g.__dispatchResponse = function (json) {
    var raw = JSON.parse(json), s = new Session(raw, 'response'), out = { action: 'continue' };
    if (typeof g.onBeforeResponse === 'function') g.onBeforeResponse(s);
    // A registerColumn(title, fn) function fills the Custom column at response time,
    // unless the script already set a custom value explicitly.
    if (s._action === 'continue' && s._custom == null && g.Quena._column && g.Quena._column.fn) {
      try { var v = g.Quena._column.fn(s); s._custom = v == null ? null : String(v); } catch (e) { __log('error', 'registerColumn fn: ' + (e && e.stack || e)); }
    }
    out.action = s._action; meta(s, out);
    if (s._action === 'continue') {
      out.status = s.status;
      out.headers = s.responseHeaders._dirty ? s.responseHeaders.toArray() : null;
    }
    return JSON.stringify(out);
  };

  // One WebSocket message: msg.text can be changed (text messages), msg.drop() keeps it
  // from being sent.
  g.__dispatchWs = function (json) {
    var raw = JSON.parse(json);
    var m = { id: raw.id, url: raw.url, direction: raw.direction, isBinary: raw.isBinary, size: raw.size, text: raw.text == null ? null : raw.text, _drop: false };
    m.drop = function () { m._drop = true; };
    if (typeof g.onWebSocketMessage === 'function') g.onWebSocketMessage(m);
    if (m._drop) return '{"action":"drop"}';
    if (!raw.isBinary && m.text !== raw.text) return JSON.stringify({ action: 'replace', text: m.text == null ? '' : String(m.text) });
    return '{"action":"forward"}';
  };

  g.__dispatchComplete = function (json) {
    if (typeof g.onSessionComplete === 'function') g.onSessionComplete(JSON.parse(json));
  };

  // Script extensibility entry points called by the host.
  g.__menus = function () { return JSON.stringify(g.Quena._menus.map(function (m) { return m.label; })); };
  g.__columnTitle = function () { return g.Quena._column ? g.Quena._column.title : null; };
  g.__runMenu = function (index, ctxJson) {
    var m = g.Quena._menus[index];
    if (!m) return '[]';
    var sessions;
    try { sessions = JSON.parse(ctxJson); } catch (e) { sessions = []; }
    var res = [];
    try {
      var r = m.handler(sessions);
      if (Array.isArray(r)) res = r;
    } catch (e) { __log('error', 'menu "' + m.label + '": ' + (e && e.stack || e)); }
    return JSON.stringify(res);
  };

  g.__boot = function () {
    if (typeof g.onBoot === 'function') g.onBoot();
  };
})(globalThis);
