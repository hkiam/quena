//! Decoder for Negotiate/NTLM/Kerberos authentication tokens: SPNEGO (RFC 4178),
//! Kerberos AP-REQ/AP-REP/KRB-ERROR (RFC 4120, GSS framing RFC 1964/2743) and
//! NTLMSSP messages (MS-NLMP). Encrypted parts (ticket, authenticator) cannot be
//! decrypted without keys; only their envelope is shown.
//!
//! Malformed input never panics: every read is bounds-checked and a parse error
//! is reported as a section of its own.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub title: String,
    pub fields: Vec<(String, String)>,
    pub notes: Vec<String>,
    pub children: Vec<Section>,
}

impl Section {
    fn new(title: impl Into<String>) -> Section {
        Section { title: title.into(), ..Default::default() }
    }
    fn field(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push((name.into(), value.into()));
    }
    /// Value of the first field `name` in this section.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
    /// Depth-first search for a section whose title starts with `prefix`.
    pub fn find(&self, prefix: &str) -> Option<&Section> {
        if self.title.starts_with(prefix) {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(prefix))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub section: Section,
    pub bytes: Vec<u8>,
}

type R<T> = Result<T, String>;

// ------------------------------------------------------------------ helpers

/// Standard or URL-safe base64, padding optional.
pub fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim().trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_dump(b: &[u8], max: usize) -> String {
    let n = b.len().min(max);
    let mut lines: Vec<String> = b[..n]
        .chunks(16)
        .enumerate()
        .map(|(i, row)| {
            let h = row.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
            let a: String = row.iter().map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' }).collect();
            format!("{:04x}  {h:<47}  {a}", i * 16)
        })
        .collect();
    if b.len() > max {
        lines.push(format!("… {} more bytes", b.len() - max));
    }
    lines.join("\n")
}

fn slice(b: &[u8], off: usize, len: usize) -> R<&[u8]> {
    off.checked_add(len).and_then(|end| b.get(off..end)).ok_or_else(|| "truncated message".to_string())
}

fn u16le(b: &[u8], o: usize) -> R<u16> {
    let s = slice(b, o, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], o: usize) -> R<u32> {
    let s = slice(b, o, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn utf16le(b: &[u8]) -> String {
    let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&u)
}

/// Windows FILETIME (100 ns since 1601) as ISO 8601 UTC.
fn filetime(b: &[u8], o: usize) -> R<String> {
    let s = slice(b, o, 8)?;
    let v = u64::from_le_bytes(s.try_into().unwrap_or_default());
    if v == 0 {
        return Ok("0".into());
    }
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if v < EPOCH_DIFF {
        return Ok(format!("0x{v:016x}"));
    }
    let ms = (v - EPOCH_DIFF) / 10_000;
    Ok(iso_utc(ms / 1000, (ms % 1000) as u32))
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SS.mmmZ` (proleptic Gregorian, civil-from-days).
fn iso_utc(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

// --------------------------------------------------------------------- DER

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    /// 0 universal, 1 application, 2 context, 3 private
    class: u8,
    tag: u32,
    value: &'a [u8],
    /// Offset after this element in the parent buffer.
    end: usize,
}

fn tlv(b: &[u8], mut o: usize) -> R<Tlv<'_>> {
    let err = || "truncated DER".to_string();
    let id = *b.get(o).ok_or_else(err)?;
    o += 1;
    let mut tag = u32::from(id & 0x1f);
    if tag == 0x1f {
        tag = 0;
        loop {
            let c = *b.get(o).ok_or_else(err)?;
            o += 1;
            tag = tag.checked_shl(7).ok_or("DER tag too large")? | u32::from(c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
        }
    }
    let mut len = usize::from(*b.get(o).ok_or_else(err)?);
    o += 1;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 {
            return Err("unsupported DER length".into());
        }
        len = 0;
        for _ in 0..n {
            len = (len << 8) | usize::from(*b.get(o).ok_or_else(err)?);
            o += 1;
        }
    }
    let value = slice(b, o, len).map_err(|_| err())?;
    Ok(Tlv { class: id >> 6, tag, value, end: o + len })
}

fn items(v: &[u8]) -> R<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut o = 0;
    while o < v.len() {
        let t = tlv(v, o)?;
        o = t.end;
        out.push(t);
    }
    Ok(out)
}

/// Contents of the explicit context tag `[n]` inside a SEQUENCE.
fn ctx<'a>(seq: &Tlv<'a>, n: u32) -> R<Option<Tlv<'a>>> {
    match items(seq.value)?.into_iter().find(|x| x.class == 2 && x.tag == n) {
        Some(t) => Ok(Some(tlv(t.value, 0)?)),
        None => Ok(None),
    }
}

fn unsigned(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |v, &x| (v << 8) | u64::from(x))
}

/// DER INTEGER (two's complement, e.g. name type -128).
fn int(t: Option<Tlv<'_>>) -> Option<i64> {
    let t = t?;
    if t.value.is_empty() || t.value.len() > 8 {
        return None;
    }
    let v = unsigned(t.value) as i64;
    Some(if t.value[0] & 0x80 != 0 && t.value.len() < 8 { v - (1i64 << (8 * t.value.len())) } else { v })
}

fn int_str(t: Option<Tlv<'_>>) -> String {
    int(t).map(|v| v.to_string()).unwrap_or_default()
}

fn oid(b: &[u8]) -> String {
    let Some(&first) = b.first() else { return String::new() };
    let mut parts = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut v = 0u64;
    for &c in &b[1..] {
        v = (v << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn text(t: Option<Tlv<'_>>) -> String {
    t.map(|t| String::from_utf8_lossy(t.value).into_owned()).unwrap_or_default()
}

/// KerberosTime `YYYYMMDDHHMMSSZ` → `YYYY-MM-DD HH:MM:SS UTC`.
fn gen_time(t: Option<Tlv<'_>>) -> String {
    let s = text(t);
    let b = s.as_bytes();
    if b.len() == 15 && b[14] == b'Z' && b[..14].iter().all(u8::is_ascii_digit) {
        format!("{}-{}-{} {}:{}:{} UTC", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14])
    } else {
        s
    }
}

// ----------------------------------------------------------------- names

fn oid_name(o: &str) -> String {
    let n = match o {
        "1.3.6.1.5.5.2" => "SPNEGO",
        "1.2.840.113554.1.2.2" => "Kerberos 5",
        "1.2.840.48018.1.2.2" => "Kerberos 5 (Microsoft legacy OID)",
        "1.2.840.113554.1.2.2.3" => "Kerberos 5 User-to-User",
        "1.3.6.1.4.1.311.2.2.10" => "NTLM",
        "1.3.6.1.4.1.311.2.2.30" => "NEGOEX",
        _ => return o.to_string(),
    };
    format!("{n} ({o})")
}

fn etype(n: Option<i64>) -> String {
    let Some(n) = n else { return "?".into() };
    let name = match n {
        1 => "des-cbc-crc",
        3 => "des-cbc-md5",
        17 => "aes128-cts-hmac-sha1-96",
        18 => "aes256-cts-hmac-sha1-96",
        19 => "aes128-cts-hmac-sha256-128",
        20 => "aes256-cts-hmac-sha384-192",
        23 => "rc4-hmac",
        24 => "rc4-hmac-exp",
        _ => "unknown",
    };
    format!("{name} ({n})")
}

fn name_type(n: i64) -> String {
    let name = match n {
        0 => "NT-UNKNOWN",
        1 => "NT-PRINCIPAL",
        2 => "NT-SRV-INST",
        3 => "NT-SRV-HST",
        10 => "NT-ENTERPRISE",
        -128 => "NT-MS-PRINCIPAL",
        _ => "unknown",
    };
    format!("{name} ({n})")
}

fn krb_error_name(n: i64) -> &'static str {
    match n {
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        14 => "KDC_ERR_ETYPE_NOSUPP",
        18 => "KDC_ERR_CLIENT_REVOKED",
        23 => "KDC_ERR_KEY_EXPIRED",
        24 => "KDC_ERR_PREAUTH_FAILED",
        25 => "KDC_ERR_PREAUTH_REQUIRED",
        31 => "KRB_AP_ERR_BAD_INTEGRITY",
        32 => "KRB_AP_ERR_TKT_EXPIRED",
        33 => "KRB_AP_ERR_TKT_NYV",
        34 => "KRB_AP_ERR_REPEAT",
        35 => "KRB_AP_ERR_NOT_US",
        36 => "KRB_AP_ERR_BADMATCH",
        37 => "KRB_AP_ERR_SKEW",
        38 => "KRB_AP_ERR_BADADDR",
        39 => "KRB_AP_ERR_BADVERSION",
        40 => "KRB_AP_ERR_MSG_TYPE",
        41 => "KRB_AP_ERR_MODIFIED",
        42 => "KRB_AP_ERR_BADORDER",
        44 => "KRB_AP_ERR_BADKEYVER",
        45 => "KRB_AP_ERR_NOKEY",
        46 => "KRB_AP_ERR_MUT_FAIL",
        47 => "KRB_AP_ERR_BADDIRECTION",
        48 => "KRB_AP_ERR_METHOD",
        60 => "KRB_ERR_GENERIC",
        68 => "KDC_ERR_WRONG_REALM",
        _ => "",
    }
}

const NEG_STATES: [&str; 4] = ["accept-completed", "accept-incomplete", "reject", "request-mic"];

// ---------------------------------------------------------------- Kerberos

struct Principal {
    kind: String,
    name: String,
}

fn principal(t: Option<Tlv<'_>>) -> R<Principal> {
    let Some(t) = t else { return Ok(Principal { kind: String::new(), name: String::new() }) };
    let kind = int(ctx(&t, 0)?).map(name_type).unwrap_or_default();
    let name = match ctx(&t, 1)? {
        Some(ns) => items(ns.value)?.iter().map(|x| String::from_utf8_lossy(x.value).into_owned()).collect::<Vec<_>>().join("/"),
        None => String::new(),
    };
    Ok(Principal { kind, name })
}

fn enc_data(s: &mut Section, t: Option<Tlv<'_>>) -> R<()> {
    let Some(t) = t else { return Ok(()) };
    s.field("Encryption type", etype(int(ctx(&t, 0)?)));
    if let Some(kvno) = int(ctx(&t, 1)?) {
        s.field("Key version (kvno)", kvno.to_string());
    }
    let cipher = ctx(&t, 2)?.map(|c| c.value.len()).unwrap_or(0);
    s.field("Cipher", format!("{cipher} bytes (encrypted)"));
    Ok(())
}

fn ap_options(t: Option<Tlv<'_>>) -> String {
    let Some(t) = t.filter(|t| t.value.len() >= 2) else { return "none".into() };
    let bits = t.value[1];
    let mut names = vec![];
    if bits & 0x40 != 0 {
        names.push("use-session-key");
    }
    if bits & 0x20 != 0 {
        names.push("mutual-required");
    }
    let h = format!("0x{}", hex(&t.value[1..]));
    if names.is_empty() { h } else { format!("{h} ({})", names.join(", ")) }
}

fn kerberos(b: &[u8]) -> R<Section> {
    let outer = tlv(b, 0)?;
    // Normally [APPLICATION n]; some stacks hand out the bare SEQUENCE, then msg-type [1] tells.
    let bare = outer.class == 0 && outer.tag == 16;
    let seq = if bare { outer } else { tlv(outer.value, 0)? };
    let kind = if bare { int(ctx(&seq, 1)?).unwrap_or(-1) } else { i64::from(outer.tag) };
    match kind {
        14 => {
            let mut s = Section::new("Kerberos AP-REQ");
            s.field("Protocol version", int_str(ctx(&seq, 0)?));
            s.field("AP options", ap_options(ctx(&seq, 2)?));
            let mut t = Section::new("Ticket");
            if let Some(app) = ctx(&seq, 3)? {
                let ticket = tlv(app.value, 0)?;
                let realm = text(ctx(&ticket, 1)?);
                let sname = principal(ctx(&ticket, 2)?)?;
                t.field("Service principal (SPN)", format!("{}@{realm}", sname.name));
                t.field("Realm", realm);
                t.field("Server name", sname.name);
                t.field("Name type", sname.kind);
                t.field("Ticket version", int_str(ctx(&ticket, 0)?));
                enc_data(&mut t, ctx(&ticket, 3)?)?;
            }
            t.notes.push("The ticket body (client name, flags, validity, PAC) is encrypted with the service key.".into());
            let mut a = Section::new("Authenticator");
            enc_data(&mut a, ctx(&seq, 4)?)?;
            a.notes.push("Encrypted with the session key (contains client name, time and the GSS checksum/delegation flags).".into());
            s.children = vec![t, a];
            Ok(s)
        }
        15 => {
            let mut s = Section::new("Kerberos AP-REP (mutual authentication)");
            s.field("Protocol version", int_str(ctx(&seq, 0)?));
            enc_data(&mut s, ctx(&seq, 2)?)?;
            Ok(s)
        }
        30 => {
            let mut s = Section::new("Kerberos KRB-ERROR");
            let code = int(ctx(&seq, 6)?);
            s.field("Error code", code.map(|c| format!("{c} {}", krb_error_name(c)).trim_end().to_string()).unwrap_or_default());
            s.field("Server time", gen_time(ctx(&seq, 4)?));
            s.field("Realm", text(ctx(&seq, 9)?));
            s.field("Server name", principal(ctx(&seq, 10)?)?.name);
            let cname = principal(ctx(&seq, 8)?)?;
            if !cname.name.is_empty() {
                s.field("Client name", format!("{}@{}", cname.name, text(ctx(&seq, 7)?)));
            }
            let e = text(ctx(&seq, 11)?);
            if !e.is_empty() {
                s.field("Error text", e);
            }
            Ok(s)
        }
        k => Ok(Section::new(format!("Kerberos message type {k}"))),
    }
}

/// GSS-API framed token: [APPLICATION 0] { mech OID, inner token }.
fn gss_framed(b: &[u8]) -> R<Section> {
    let app = tlv(b, 0)?;
    let o = tlv(app.value, 0)?;
    let mech = oid(o.value);
    let inner = &app.value[o.end..];
    if mech == "1.3.6.1.5.5.2" {
        return neg_token_init(tlv(inner, 0)?);
    }
    if mech.starts_with("1.2.840.113554.1.2.2") || mech == "1.2.840.48018.1.2.2" {
        let tok_id = u16::from_be_bytes([*inner.first().unwrap_or(&0), *inner.get(1).unwrap_or(&0)]);
        let mut k = kerberos(inner.get(2..).unwrap_or_default())?;
        k.fields.insert(0, ("GSS mechanism".into(), oid_name(&mech)));
        k.fields.insert(1, ("GSS token id".into(), format!("0x{tok_id:04x}")));
        return Ok(k);
    }
    let mut s = Section::new("GSS-API token");
    s.field("Mechanism", oid_name(&mech));
    s.field("Inner token", format!("{} bytes", inner.len()));
    Ok(s)
}

// ------------------------------------------------------------------ SPNEGO

fn mech_token(b: &[u8]) -> R<Section> {
    if is_ntlm(b) {
        return ntlm(b);
    }
    match b.first() {
        Some(0x60) => gss_framed(b),
        Some(0x6e | 0x6f | 0x7e) => kerberos(b),
        _ => {
            let mut s = Section::new("Mechanism token");
            s.field("Length", format!("{} bytes", b.len()));
            Ok(s)
        }
    }
}

fn neg_token_init(t: Tlv<'_>) -> R<Section> {
    let seq = tlv(t.value, 0)?;
    let mut s = Section::new("SPNEGO NegTokenInit");
    if let Some(mt) = ctx(&seq, 0)? {
        for (i, m) in items(mt.value)?.iter().enumerate() {
            s.field(if i == 0 { "Mechanisms (preferred first)" } else { "" }, oid_name(&oid(m.value)));
        }
    }
    if let Some(mic) = ctx(&seq, 3)? {
        s.field("mechListMIC", format!("{} bytes", mic.value.len()));
    }
    if let Some(tok) = ctx(&seq, 2)? {
        s.children.push(mech_token(tok.value)?);
    }
    Ok(s)
}

fn neg_token_resp(t: Tlv<'_>) -> R<Section> {
    let seq = tlv(t.value, 0)?;
    let mut s = Section::new("SPNEGO NegTokenResp");
    if let Some(st) = ctx(&seq, 0)? {
        let n = unsigned(st.value) as usize;
        s.field("Negotiation state", format!("{} ({n})", NEG_STATES.get(n).unwrap_or(&"?")));
    }
    if let Some(sm) = ctx(&seq, 1)? {
        s.field("Supported mechanism", oid_name(&oid(sm.value)));
    }
    if let Some(mic) = ctx(&seq, 3)? {
        s.field("mechListMIC", format!("{} bytes", mic.value.len()));
    }
    if let Some(rt) = ctx(&seq, 2)? {
        s.children.push(mech_token(rt.value)?);
    }
    Ok(s)
}

// -------------------------------------------------------------------- NTLM

const NTLM_FLAGS: [(u32, &str); 22] = [
    (0x0000_0001, "UNICODE"),
    (0x0000_0002, "OEM"),
    (0x0000_0004, "REQUEST_TARGET"),
    (0x0000_0010, "SIGN"),
    (0x0000_0020, "SEAL"),
    (0x0000_0040, "DATAGRAM"),
    (0x0000_0080, "LM_KEY"),
    (0x0000_0200, "NTLM"),
    (0x0000_0800, "ANONYMOUS"),
    (0x0000_1000, "OEM_DOMAIN_SUPPLIED"),
    (0x0000_2000, "OEM_WORKSTATION_SUPPLIED"),
    (0x0000_8000, "ALWAYS_SIGN"),
    (0x0001_0000, "TARGET_TYPE_DOMAIN"),
    (0x0002_0000, "TARGET_TYPE_SERVER"),
    (0x0008_0000, "EXTENDED_SESSIONSECURITY"),
    (0x0010_0000, "IDENTIFY"),
    (0x0040_0000, "REQUEST_NON_NT_SESSION_KEY"),
    (0x0080_0000, "TARGET_INFO"),
    (0x0200_0000, "VERSION"),
    (0x2000_0000, "128"),
    (0x4000_0000, "KEY_EXCH"),
    (0x8000_0000, "56"),
];

const F_UNICODE: u32 = 0x0000_0001;
const F_VERSION: u32 = 0x0200_0000;

fn flag_list(f: u32) -> String {
    let names: Vec<&str> = NTLM_FLAGS.iter().filter(|(m, _)| f & m == *m).map(|(_, n)| *n).collect();
    format!("0x{f:08x}  {}", names.join(" | "))
}

fn av_name(id: u16) -> String {
    match id {
        1 => "NetBIOS computer",
        2 => "NetBIOS domain",
        3 => "DNS computer",
        4 => "DNS domain",
        5 => "DNS tree",
        6 => "Flags",
        7 => "Timestamp",
        8 => "Single host",
        9 => "Target name (SPN)",
        10 => "Channel bindings",
        _ => return format!("AV {id}"),
    }
    .to_string()
}

fn is_ntlm(b: &[u8]) -> bool {
    b.len() >= 12 && b.starts_with(b"NTLMSSP\0")
}

/// NTLM security buffer (len, maxlen, offset) at `o`; empty when out of range.
fn sec_buf(b: &[u8], o: usize) -> &[u8] {
    let (Ok(len), Ok(off)) = (u16le(b, o), u32le(b, o + 4)) else { return &[] };
    slice(b, off as usize, len as usize).unwrap_or(&[])
}

fn version(b: &[u8], o: usize) -> Option<String> {
    let v = slice(b, o, 8).ok()?;
    Some(format!("{}.{} (build {}), NTLM revision {}", v[0], v[1], u16::from_le_bytes([v[2], v[3]]), v[7]))
}

fn av_pairs(b: &[u8]) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut o = 0;
    while let (Ok(id), Ok(len)) = (u16le(b, o), u16le(b, o + 2)) {
        let Ok(v) = slice(b, o + 4, len as usize) else { break };
        o += 4 + len as usize;
        if id == 0 {
            break;
        }
        let value = match id {
            6 => u32le(v, 0).map(|f| format!("0x{f:08x}")).unwrap_or_default(),
            7 => filetime(v, 0).unwrap_or_default(),
            8 | 10 => hex(v),
            _ => utf16le(v),
        };
        out.push((av_name(id), value));
    }
    out
}

fn ntlm(b: &[u8]) -> R<Section> {
    match u32le(b, 8)? {
        1 => {
            let flags = u32le(b, 12)?;
            let mut s = Section::new("NTLM Type 1 (Negotiate)");
            s.field("Flags", flag_list(flags));
            let dom = latin1(sec_buf(b, 16));
            let ws = latin1(sec_buf(b, 24));
            if !dom.is_empty() {
                s.field("Domain", dom);
            }
            if !ws.is_empty() {
                s.field("Workstation", ws);
            }
            if flags & F_VERSION != 0 {
                if let Some(v) = version(b, 32) {
                    s.field("OS version", v);
                }
            }
            Ok(s)
        }
        2 => {
            let flags = u32le(b, 20)?;
            let str_ = |x: &[u8]| if flags & F_UNICODE != 0 { utf16le(x) } else { latin1(x) };
            let mut s = Section::new("NTLM Type 2 (Challenge)");
            s.field("Flags", flag_list(flags));
            s.field("Target name", str_(sec_buf(b, 12)));
            s.field("Server challenge", hex(slice(b, 24, 8)?));
            if flags & F_VERSION != 0 && b.len() >= 56 {
                if let Some(v) = version(b, 48) {
                    s.field("OS version", v);
                }
            }
            let ti = if b.len() >= 48 { av_pairs(sec_buf(b, 40)) } else { vec![] };
            if !ti.is_empty() {
                s.children.push(Section { title: "Target info".into(), fields: ti, ..Default::default() });
            }
            Ok(s)
        }
        3 => {
            let flags = u32le(b, 60)?;
            let str_ = |x: &[u8]| if flags & F_UNICODE != 0 { utf16le(x) } else { latin1(x) };
            let lm = sec_buf(b, 12);
            let nt = sec_buf(b, 20);
            let mut s = Section::new("NTLM Type 3 (Authenticate)");
            s.field("Domain", str_(sec_buf(b, 28)));
            s.field("User", str_(sec_buf(b, 36)));
            s.field("Workstation", str_(sec_buf(b, 44)));
            s.field("Flags", flag_list(flags));
            s.field("LM response", format!("{} bytes", lm.len()));
            let kind = match nt.len() {
                0 => "empty/anonymous",
                24 => "NTLMv1",
                n if n > 24 => "NTLMv2",
                _ => "invalid",
            };
            s.field("NT response", format!("{} bytes ({kind})", nt.len()));
            s.field("Session key", format!("{} bytes", sec_buf(b, 52).len()));
            if flags & F_VERSION != 0 && b.len() >= 72 {
                if let Some(v) = version(b, 64) {
                    s.field("OS version", v);
                }
            }
            if nt.len() > 44 {
                // NTLMv2: NTProofStr(16) + blob { resp type, reserved, timestamp @8, client challenge @16, AV pairs @28 }
                let blob = &nt[16..];
                let mut v2 = Section::new("NTLMv2 response");
                v2.field("Timestamp", filetime(blob, 8)?);
                v2.field("Client challenge", hex(slice(blob, 16, 8)?));
                v2.fields.extend(av_pairs(blob.get(28..).unwrap_or_default()));
                s.children.push(v2);
            }
            Ok(s)
        }
        t => Ok(Section::new(format!("NTLM message type {t}"))),
    }
}

// --------------------------------------------------------------------- API

pub const SCHEMES: [&str; 3] = ["negotiate", "ntlm", "kerberos"];

/// Decode the token of scheme Negotiate/NTLM/Kerberos. `None` when there is no token.
pub fn decode(scheme: &str, token: &str) -> Option<Decoded> {
    let s = scheme.to_ascii_lowercase();
    if !SCHEMES.contains(&s.as_str()) || token.trim().is_empty() {
        return None;
    }
    let Some(b) = base64(token).filter(|b| !b.is_empty()) else {
        let mut sec = Section::new("Invalid token");
        sec.notes.push("The value is not valid Base64.".into());
        return Some(Decoded { section: sec, bytes: vec![] });
    };
    let parsed = if is_ntlm(&b) {
        ntlm(&b)
    } else {
        match b[0] {
            0x60 => gss_framed(&b),
            0xa1 => tlv(&b, 0).and_then(neg_token_resp),
            0xa0 => tlv(&b, 0).and_then(neg_token_init),
            0x6e | 0x6f | 0x7e | 0x30 => kerberos(&b),
            _ => {
                let mut s = Section::new("Unknown token");
                s.field("Length", format!("{} bytes", b.len()));
                Ok(s)
            }
        }
    };
    let mut section = parsed.unwrap_or_else(|e| {
        let mut s = Section::new("Token could not be parsed");
        s.notes.push(e);
        s
    });
    // Client messages (Type 1/3) only; a Type 2 is the server's answer to such a fallback.
    if s == "negotiate" && is_ntlm(&b) && u32le(&b, 8).ok() != Some(2) {
        section.notes.push(
            "Negotiate carries a raw NTLM message: the client found no Kerberos ticket for the service principal (e.g. the SPN is not registered or was built from a CNAME alias) and fell back to NTLM."
                .into(),
        );
    }
    Some(Decoded { section, bytes: b })
}

/// Split `Scheme token` and decode it when it is a token of a supported scheme.
/// Challenges with parameters (`Basic realm="x"`) are not tokens.
pub fn decode_header_value(value: &str) -> Option<Decoded> {
    let (scheme, cred) = value.trim().split_once(' ').unwrap_or((value.trim(), ""));
    let cred = cred.trim();
    let is_token = !cred.is_empty()
        && cred.trim_end_matches('=').bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'-' | b'_'))
        && cred.len() - cred.trim_end_matches('=').len() <= 2;
    if !is_token {
        return None;
    }
    decode(scheme, cred)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Section,
    Field,
    Note,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub depth: u8,
    pub kind: NodeKind,
    pub name: String,
    pub value: String,
}

fn flatten(s: &Section, depth: u8, out: &mut Vec<Node>) {
    let node = |kind, name: &str, value: &str| Node { depth, kind, name: name.to_string(), value: value.to_string() };
    out.push(node(NodeKind::Section, &s.title, ""));
    out.extend(s.fields.iter().map(|(n, v)| node(NodeKind::Field, n, v)));
    out.extend(s.notes.iter().map(|n| node(NodeKind::Note, "", n)));
    for c in &s.children {
        flatten(c, depth.saturating_add(1), out);
    }
}

/// The flattened result tree for the plugin API, followed by a hex dump.
pub fn nodes(d: &Decoded) -> Vec<Node> {
    let mut out = vec![];
    flatten(&d.section, 0, &mut out);
    if !d.bytes.is_empty() {
        out.push(Node { depth: 0, kind: NodeKind::Code, name: format!("Raw token ({} bytes)", d.bytes.len()), value: hex_dump(&d.bytes, 4096) });
    }
    out
}
