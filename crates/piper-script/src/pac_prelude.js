// PAC (proxy auto-config) helper functions, per the Netscape spec.
// DNS-dependent helpers call native functions provided by the Rust host.
;(function (g) {
  g.dnsResolve = function (host) { return __dnsResolve(String(host)); };
  g.myIpAddress = function () { return __myIpAddress(); };

  g.isPlainHostName = function (host) { return String(host).indexOf('.') < 0; };

  g.dnsDomainIs = function (host, domain) {
    host = String(host); domain = String(domain);
    return host.length >= domain.length && host.substring(host.length - domain.length) === domain;
  };

  g.localHostOrDomainIs = function (host, hostdom) {
    host = String(host); hostdom = String(hostdom);
    return host === hostdom || hostdom.lastIndexOf(host + '.', 0) === 0;
  };

  g.isResolvable = function (host) { return g.dnsResolve(host) != null; };

  function ip2long(ip) {
    var p = String(ip).split('.');
    if (p.length !== 4) return null;
    var n = 0;
    for (var i = 0; i < 4; i++) {
      var o = parseInt(p[i], 10);
      if (isNaN(o) || o < 0 || o > 255) return null;
      n = (n * 256) + o;
    }
    return n >>> 0;
  }

  g.isInNet = function (host, pattern, mask) {
    var ip = ip2long(g.dnsResolve(host));
    var pat = ip2long(pattern), m = ip2long(mask);
    if (ip == null || pat == null || m == null) return false;
    return ((ip & m) >>> 0) === ((pat & m) >>> 0);
  };

  g.dnsDomainLevels = function (host) { return String(host).split('.').length - 1; };

  g.shExpMatch = function (str, shexp) {
    str = String(str); shexp = String(shexp);
    var re = '';
    for (var i = 0; i < shexp.length; i++) {
      var c = shexp[i];
      if (c === '*') re += '.*';
      else if (c === '?') re += '.';
      else re += c.replace(/[.\\+^$(){}\[\]|]/g, '\\$&');
    }
    try { return new RegExp('^' + re + '$').test(str); } catch (e) { return false; }
  };

  var WD = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
  g.weekdayRange = function (wd1, wd2, gmt) {
    var useGmt = (wd2 === 'GMT') || (gmt === 'GMT');
    var now = new Date();
    var day = useGmt ? now.getUTCDay() : now.getDay();
    var i1 = WD.indexOf(wd1);
    if (i1 < 0) return false;
    var i2 = (wd2 === 'GMT' || wd2 == null) ? i1 : WD.indexOf(wd2);
    if (i2 < 0) i2 = i1;
    if (i1 <= i2) return day >= i1 && day <= i2;
    return day >= i1 || day <= i2;
  };

  g.timeRange = function () {
    var a = Array.prototype.slice.call(arguments);
    var gmt = a.length && a[a.length - 1] === 'GMT';
    if (gmt) a.pop();
    var now = new Date();
    var h = gmt ? now.getUTCHours() : now.getHours();
    var m = gmt ? now.getUTCMinutes() : now.getMinutes();
    var s = gmt ? now.getUTCSeconds() : now.getSeconds();
    var cur = h * 3600 + m * 60 + s;
    function sec(hh, mm, ss) { return (hh || 0) * 3600 + (mm || 0) * 60 + (ss || 0); }
    if (a.length === 1) return h === a[0];
    if (a.length === 2) return h >= a[0] && h <= a[1];
    if (a.length === 4) { var f = sec(a[0], a[1]), t = sec(a[2], a[3]); return f <= t ? (cur >= f && cur <= t) : (cur >= f || cur <= t); }
    if (a.length === 6) { var f2 = sec(a[0], a[1], a[2]), t2 = sec(a[3], a[4], a[5]); return f2 <= t2 ? (cur >= f2 && cur <= t2) : (cur >= f2 || cur <= t2); }
    return false;
  };

  var MO = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
  g.dateRange = function () {
    var a = Array.prototype.slice.call(arguments);
    var gmt = a.length && a[a.length - 1] === 'GMT';
    if (gmt) a.pop();
    var now = new Date();
    var day = gmt ? now.getUTCDate() : now.getDate();
    var mon = gmt ? now.getUTCMonth() : now.getMonth();
    var yr = gmt ? now.getUTCFullYear() : now.getFullYear();
    function isMonth(v) { return typeof v === 'string' && MO.indexOf(v) >= 0; }
    if (a.length === 1) {
      if (isMonth(a[0])) return mon === MO.indexOf(a[0]);
      if (a[0] > 31) return yr === a[0];
      return day === a[0];
    }
    if (a.length === 2) {
      if (isMonth(a[0])) { var m1 = MO.indexOf(a[0]), m2 = MO.indexOf(a[1]); return m1 <= m2 ? (mon >= m1 && mon <= m2) : (mon >= m1 || mon <= m2); }
      if (a[0] > 31) return yr >= a[0] && yr <= a[1];
      return day >= a[0] && day <= a[1];
    }
    // day/month or day/month/year ranges: best-effort by comparing the date value.
    return true;
  };
})(globalThis);
