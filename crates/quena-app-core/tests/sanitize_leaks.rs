//! Leak regressions of the sanitized export: every case a review found (secret field names,
//! authorization relatives, program code, nested pairs, `key: value` forms, name/value
//! indirection, e-mail and phone corner cases, IP hosts, HTML forms, WebSocket compression
//! and fragments, other identity carriers, path tokens) as marker values in one capture,
//! exported as SAZ and HAR with the `gdpr` and `support` presets. No marker may survive, the
//! structure must stay valid, and values that only look like secrets must stay. Also:
//! cancellation and a timing bound for large bodies.
use quena_app_core::archive::{ArchiveFormat, sanitized_export};
use quena_app_core::sanitize::{SanitizeOptions, Sanitizer};
use quena_model::{
    Headers, ProcessInfo, RequestHead, ResponseHead, SessionDetail, SessionId, SessionKind,
};
use quena_store::Capture;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

/// Markers that no preset may keep.
const SECRETS: &[&str] = &[
    "LKURLPW",
    "LKPATH12",
    "LKJSESS",
    "LKQTOK",
    "LKQPWD",
    "LKQHASH",
    "LKFRAG",
    "LKXFA12345",
    "TEtCQVNJQzE",
    "LKBEARERHDR",
    "TEtYQkFTSUM",
    "LKWSPROTO",
    "TEtQUklOQ0lQQUw",
    "LKREFPW",
    "LKLINK",
    "LKREFRESH",
    "LKTXTBEARER",
    "LKTXTCOOKIE",
    "LKNESTED1",
    "LKNESTED2",
    "LKCOLON",
    "LKQUOTED",
    "LKSQ",
    "LKJ01",
    "LKJ02",
    "LKJ03",
    "LKJ04",
    "LKJ05",
    "LKJ06",
    "LKJ07",
    "LKJ08",
    "LKJ09",
    "LKJ10",
    "LKJ11",
    "LKJ12",
    "LKJ13",
    "LKJ14",
    "LKJ15",
    "LKJ16",
    "LKJ17",
    "LKNV1",
    "LKNV3",
    "LKGQL",
    "LKF1",
    "LKF2",
    "LKF3",
    "LKF4",
    "LKMP1",
    "LKXP",
    "LKXC",
    "LKXWP",
    "LKXNONCE",
    "LKXBST",
    "LKXSIG",
    "LKMETA",
    "LKUQ",
    "LKHCSRF",
    "LKHREF",
    "LKFORM",
    "LKJS1",
    "LKJS2",
    "LKJS3",
    "LKCSS",
    "LKY1",
    "LKY2",
    "LKY3",
    "LKBIN",
    "LKCUT1",
    "LKWS1",
    "LKWS2",
    "LKWS3",
    "LKWSFRAG",
    "LKWSOLD",
    "LKAUTOPW",
    "LKRESET0123456789ab",
    "lk.mail",
    "lk.max",
    "lk_inv",
    "lkbrien",
    "lkent",
    "lküml",
    "lknv2",
    "lkc@",
    "lk.principal",
    "DE89370400440532013000",
    "de89 3704",
    "DE89 3704",
    "4111 1111",
    "1111-1111",
    "4111111111111111",
];

/// Markers the `gdpr` preset must not keep (personal data).
const PERSONAL: &[&str] = &[
    "lkfwduser",
    "lkremote",
    "LK Cert Person",
    "203.0.113.60",
    "203.0.113.61",
    "2345678",
    "3456789",
    "4567890",
    "5678901",
    "234-5678",
    "6789012",
    "LKCUSTNAME",
    "LKWSUSER",
    "lkuser",
    "lkattr@",
    "198.51.100.77",
];

/// Values that only look like secrets or personal data: they stay with every preset.
const KEEP: &[&str] = &[
    "\"key\":\"KEEP-TITLE\"",
    "\"key\":5",
    "\"code\":\"DE\"",
    "\"code\":200",
    "KEEP-PASSENGER",
    "KEEP-COMPASS",
    "KEEP-KEYBOARD",
    "KEEP-WIDGET",
    "\"token_type\":\"bearer\"",
    "token_type=bearer",
    "version 1.2.3.4",
    "Basic information",
    "\"name\":\"password\"",
    "Type=\"PasswordText\"",
    "var code=n.code;",
    "2024-01-15",
    "Created>2024-01-01<",
    "\"name\":\"color\",\"value\":\"blue\"",
];

fn headers(h: &[(&str, &str)]) -> Headers {
    let mut out = Headers::new();
    for (k, v) in h {
        out.push(*k, *v);
    }
    out
}

fn detail(method: &str, url: &str, req: &[(&str, &str)], resp: &[(&str, &str)]) -> SessionDetail {
    let mut d = SessionDetail {
        request: RequestHead {
            method: method.into(),
            url: url.into(),
            headers: headers(req),
            ..Default::default()
        },
        response: Some(ResponseHead {
            status: 200,
            reason: "OK".into(),
            headers: headers(resp),
            ..Default::default()
        }),
        process: Some(ProcessInfo {
            pid: 1,
            name: "browser".into(),
        }),
        ..Default::default()
    };
    d.summary.started_at = 1_790_000_000_000_000;
    d
}

fn add(cap: &Arc<Capture>, d: SessionDetail, req: &[u8], resp: &[u8]) -> SessionId {
    let (rq, rs) = (cap.bodies.store_bytes(req), cap.bodies.store_bytes(resp));
    cap.insert(d, rq, rs)
}

/// One frame record of the WebSocket log (see `quena-proxy::wsframe`).
fn rec(dir: u8, op: u8, fin: bool, rsv: u8, p: &[u8]) -> Vec<u8> {
    let mut r = vec![dir, op, fin as u8, rsv];
    r.extend_from_slice(&5i64.to_le_bytes());
    r.extend_from_slice(&(p.len() as u32).to_le_bytes());
    r.extend_from_slice(p);
    r
}

/// permessage-deflate: raw deflate with a sync flush, the trailing `00 00 ff ff` removed;
/// the compressor keeps its window between messages (context takeover).
fn deflate_msg(c: &mut flate2::Compress, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 64);
    c.compress_vec(msg, &mut out, flate2::FlushCompress::Sync)
        .unwrap();
    assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
    out.truncate(out.len() - 4);
    out
}

fn fill(cap: &Arc<Capture>) -> Vec<SessionId> {
    let mut ids = Vec::new();
    // 1: URL, authorization relatives and other identity headers; text body with credentials,
    //    nested pairs, `key: value` forms, phone / e-mail / IBAN / card corner cases.
    let text = "Authorization: Bearer LKTXTBEARER1\nCookie: s=LKTXTCOOKIE; t=x\nsee url=https://h.test/?token=LKNESTED1 and next=/login?password=LKNESTED2\n\
secret: LKCOLON\npassword = \"LKQUOTED one\"; 'api_key': 'LKSQ'\ncall 030 2345678 / 0170 3456789, (030) 4567890 und 0171 5678901, +1 (555) 234-5678 0049 30 6789012\n\
mail lk.max@firma.de.pdf lk_inv_john.doe@example.com_DE89370400440532013000.pdf o'lkbrien@firma.ie lkent&#64;example.com lküml@bücher.de\n\
iban de89 3704 0044 0532 0130 00 card 4111 1111-1111 1111 version 1.2.3.4 token_type=bearer Basic information 2024-01-15\n";
    let d = detail(
        "GET",
        "https://alice:LKURLPW@api.example.test/users/lk.mail@example.com/token/LKPATH12;jsessionid=LKJSESS/reset/LKRESET0123456789ab?access_token=LKQTOK&pwd=LKQPWD&hash=LKQHASH9f00b204e98&token_type=bearer#id_token=LKFRAG",
        &[
            ("Host", "203.0.113.60"),
            ("X-Forwarded-Authorization", "Bearer LKXFA12345"),
            ("X-Amzn-Remapped-Authorization", "Basic TEtCQVNJQzE="),
            ("Bearer", "LKBEARERHDR"),
            ("X-Basic", "Basic TEtYQkFTSUM="),
            (
                "Sec-WebSocket-Protocol",
                "access_token, LKWSPROTO1234567890abc",
            ),
            ("X-Forwarded-User", "lkfwduser"),
            ("X-Remote-User", "lkremote"),
            ("X-MS-CLIENT-PRINCIPAL-NAME", "lk.principal@example.com"),
            ("X-Ms-Client-Principal", "TEtQUklOQ0lQQUw="),
            ("X-SSL-Client-DN", "CN=LK Cert Person,O=Corp"),
            ("Referer", "/next?password=LKREFPW"),
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ],
        &[
            ("Content-Type", "text/plain"),
            ("Link", "</n?session=LKLINK>; rel=\"next\""),
            ("Refresh", "0; url=/x?token=LKREFRESH"),
            ("Content-MD5", "abc"),
            ("ETag", "\"v1\""),
            ("Digest", "sha-256=abc"),
        ],
    );
    ids.push(add(cap, d, b"", text.as_bytes()));
    // 2: JSON names, name/value indirection, GraphQL arguments, the bearer token again.
    let json = r#"{"pwd":"LKJ01","pass":"LKJ02","passphrase":"LKJ03","pin_code":"LKJ04","otpCode":"LKJ05","mfaCode":"LKJ06","verificationCode":"LKJ07","recoveryCode":"LKJ08","securityAnswer":"LKJ09","bearer":"LKJ10","accessKey":"LKJ11","key":"LKJ12xQ2eZvKYlo2C0aBcD","refresh":"LKJ13def0123456789abcd","i18n":[{"key":"KEEP-TITLE"},{"key":5},{"code":"DE"},{"code":200}],"authCode":"LKJ14","csrf":"LKJ15","xsrf":"LKJ16","SAMLResponse":"LKJ17","passenger":"KEEP-PASSENGER","compass":"KEEP-COMPASS","keyboard":"KEEP-KEYBOARD","token_type":"bearer","fields":[{"name":"password","value":"LKNV1"},{"name":"email","value":"lknv2@example.com"},{"Name":"client_secret","Value":"LKNV3"},{"name":"color","value":"blue"}],"product":{"name":"KEEP-WIDGET"},"customer":{"name":"LKCUSTNAME","email":"lkc@example.com"},"schema":{"name":"password"},"query":"mutation { login(password: \"LKGQL\") { ok } }"}"#;
    let d = detail(
        "POST",
        "https://api.example.test/login",
        &[("Content-Type", "application/json")],
        &[("Content-Type", "application/json")],
    );
    ids.push(add(
        cap,
        d,
        json.as_bytes(),
        br#"{"access_token":"LKXFA12345","ok":true}"#,
    ));
    // 3: form and multipart (a Latin-1 text part).
    let d = detail(
        "POST",
        "https://api.example.test/form",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &[],
    );
    ids.push(add(
        cap,
        d,
        b"pwd=LKF1&passphrase=LKF2&otpCode=LKF3&csrf=LKF4&lang=de",
        b"",
    ));
    let mut mp = b"--BB\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nGr\xfc\xdfe password=LKMP1\r\n--BB--\r\n".to_vec();
    mp.extend_from_slice(b"");
    let d = detail(
        "POST",
        "https://api.example.test/up",
        &[("Content-Type", "multipart/form-data; boundary=BB")],
        &[],
    );
    ids.push(add(cap, d, &mp, b""));
    // 4: SOAP / SAML: wrappers, secret leaves, name attributes.
    let soap = r#"<?xml version="1.0"?><s:Envelope xmlns:s="x" xmlns:wsse="y" xmlns:wsu="u"><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>LKWSUSER</wsse:Username><wsse:Password Type="PasswordText">LKXWP</wsse:Password><wsse:Nonce>LKXNONCE</wsse:Nonce><wsu:Created>2024-01-01</wsu:Created></wsse:UsernameToken><wsse:BinarySecurityToken>LKXBST</wsse:BinarySecurityToken></wsse:Security><saml:Assertion xmlns:saml="z"><saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue>lkattr@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><ds:SignatureValue xmlns:ds="d">LKXSIG</ds:SignatureValue></saml:Assertion></s:Header><s:Body><Parameter name="password">LKXP</Parameter><property name="client_secret" value="LKXC"/></s:Body></s:Envelope>"#;
    let d = detail(
        "POST",
        "https://api.example.test/soap",
        &[("Content-Type", "text/xml; charset=utf-8")],
        &[],
    );
    ids.push(add(cap, d, soap.as_bytes(), b""));
    // 5: HTML, JavaScript, CSS, YAML.
    let html = r#"<html><head><meta name="csrf-token" content="LKMETA"></head><body><form action="/login?sid=LKFORM"><input name=password value=LKUQ><input type=hidden name=csrf value=LKHCSRF></form><a href="/reset?token=LKHREF&amp;x=1">r</a></body></html>"#;
    let d = detail(
        "GET",
        "https://api.example.test/page",
        &[],
        &[("Content-Type", "text/html")],
    );
    ids.push(add(cap, d, b"", html.as_bytes()));
    let js = r#"var code=n.code; const API_KEY="LKJS1"; fetch("https://h.test/x?access_token=LKJS2"); x.secret = 'LKJS3';"#;
    let d = detail(
        "GET",
        "https://api.example.test/app.js",
        &[],
        &[("Content-Type", "application/javascript")],
    );
    ids.push(add(cap, d, b"", js.as_bytes()));
    let d = detail(
        "GET",
        "https://api.example.test/a.css",
        &[],
        &[("Content-Type", "text/css")],
    );
    ids.push(add(cap, d, b"", b".a{background:url(/i.png?token=LKCSS)}"));
    let d = detail(
        "GET",
        "https://api.example.test/c.yaml",
        &[],
        &[("Content-Type", "application/yaml")],
    );
    ids.push(add(
        cap,
        d,
        b"",
        b"password: LKY1\napi_key: \"LKY2\"\nclient_secret: 'LKY3'\n",
    ));
    // 6: binary data sent as text; a gzip body cut short.
    let d = detail(
        "GET",
        "https://api.example.test/bin",
        &[],
        &[("Content-Type", "text/plain")],
    );
    ids.push(add(cap, d, b"", b"\x00\x01\x02\x00password=LKBIN\x00\x00"));
    let mut long = b"password=LKCUT1 ".to_vec();
    for i in 0..4000u32 {
        long.extend_from_slice(format!("line {i} {}\n", i.wrapping_mul(2654435761)).as_bytes());
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&long).unwrap();
    let mut gz = gz.finish().unwrap();
    gz.truncate(gz.len() / 2);
    let d = detail(
        "GET",
        "https://api.example.test/cut",
        &[],
        &[("Content-Type", "text/plain"), ("Content-Encoding", "gzip")],
    );
    ids.push(add(cap, d, b"", &gz));
    // 7: WebSocket with permessage-deflate (context takeover), a fragmented text message, and
    //    a compressed message from a log without RSV bits.
    let mut client = flate2::Compress::new(flate2::Compression::default(), false);
    let mut server = flate2::Compress::new(flate2::Compression::default(), false);
    let mut log = rec(
        0,
        1,
        true,
        4,
        &deflate_msg(&mut client, br#"{"type":"auth","token":"LKWS1"}"#),
    );
    log.extend(rec(
        0,
        1,
        true,
        4,
        &deflate_msg(&mut client, br#"{"type":"auth","token":"LKWS2"}"#),
    ));
    log.extend(rec(
        1,
        1,
        true,
        4,
        &deflate_msg(&mut server, b"password=LKWS3"),
    ));
    let old = deflate_msg(&mut server, b"secret: LKWSOLD");
    assert!(std::str::from_utf8(&old).is_err());
    log.extend(rec(1, 1, true, 0, &old));
    log.extend(rec(1, 1, false, 0, b"{\"pass"));
    log.extend(rec(1, 9, true, 0, b""));
    log.extend(rec(1, 0, false, 0, b"word\":\"LKWS"));
    log.extend(rec(1, 0, true, 0, b"FRAG\"}"));
    let mut d = detail(
        "GET",
        "wss://ws.example.test/socket",
        &[],
        &[(
            "Sec-WebSocket-Extensions",
            "permessage-deflate; client_max_window_bits",
        )],
    );
    d.summary.kind = SessionKind::WebSocket;
    d.response.as_mut().unwrap().status = 101;
    ids.push(add(cap, d, b"", &log));
    // 8: a tunnel to an IP address; Fiddler flags with a user name and credentials.
    let mut d = detail(
        "CONNECT",
        "203.0.113.61:443",
        &[("Host", "203.0.113.61:443")],
        &[],
    );
    d.summary.kind = SessionKind::Tunnel;
    d.extra_flags = vec![
        ("x-UserName".into(), "CORP\\lkuser".into()),
        ("x-AutoAuth".into(), "lkauto:LKAUTOPW".into()),
        ("x-overrideHost".into(), "198.51.100.77".into()),
    ];
    ids.push(add(cap, d, b"", b""));
    cap.index.tick();
    ids
}

/// All text of a SAZ archive.
fn saz_text(path: &Path) -> String {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut all = String::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).unwrap();
        let name = f.name().to_string();
        let mut b = Vec::new();
        f.read_to_end(&mut b).unwrap();
        all.push_str(&format!("\n=== {name}\n{}", String::from_utf8_lossy(&b)));
    }
    all
}

/// All text of a HAR, with base64 bodies decoded.
fn har_text(path: &Path) -> (String, serde_json::Value) {
    let t = std::fs::read_to_string(path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&t).unwrap();
    let mut all = t.clone();
    for e in v["log"]["entries"].as_array().unwrap() {
        let c = &e["response"]["content"];
        if c["encoding"] == "base64" {
            all.push_str(&String::from_utf8_lossy(&b64(c["text"]
                .as_str()
                .unwrap_or(""))));
        }
        // Plain JSON strings, unescaped.
        all.push_str(&e.to_string().replace("\\\"", "\""));
    }
    (all, v)
}

fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bits: Vec<u8> = s.bytes().filter_map(val).collect();
    let mut out = Vec::new();
    for ch in bits.chunks(4) {
        let n = ch
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &x)| a | (x as u32) << (18 - 6 * i));
        for i in 0..ch.len().saturating_sub(1) {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn export(
    cap: &Arc<Capture>,
    ids: &[SessionId],
    dir: &Path,
    name: &str,
    format: ArchiveFormat,
    preset: &str,
) -> std::path::PathBuf {
    let path = dir.join(name);
    let opts = SanitizeOptions::preset(preset).unwrap();
    sanitized_export(
        cap,
        ids,
        &path,
        format,
        opts,
        &dir.join("tmp"),
        Default::default(),
        &quena_formats::NoProgress,
    )
    .unwrap();
    path
}

fn check(what: &str, text: &str, preset: &str) {
    for m in SECRETS {
        assert!(!text.contains(m), "{what}: {m:?} survived:\n{text}");
    }
    if preset == "gdpr" {
        for m in PERSONAL {
            assert!(!text.contains(m), "{what}: {m:?} survived:\n{text}");
        }
    }
    for k in KEEP {
        assert!(text.contains(k), "{what}: {k:?} is gone:\n{text}");
    }
}

#[test]
fn no_marker_survives_and_structure_stays() {
    let tmp = tempfile::tempdir().unwrap();
    let cap = Capture::open(tmp.path().join("cap"), Default::default(), true).unwrap();
    let ids = fill(&cap);
    for preset in ["gdpr", "support"] {
        let saz = export(
            &cap,
            &ids,
            tmp.path(),
            &format!("{preset}.saz"),
            ArchiveFormat::Saz,
            preset,
        );
        let saz_all = saz_text(&saz);
        check(&format!("{preset} SAZ"), &saz_all, preset);
        let (har_all, v) = har_text(&export(
            &cap,
            &ids,
            tmp.path(),
            &format!("{preset}.har"),
            ArchiveFormat::Har,
            preset,
        ));
        check(&format!("{preset} HAR"), &har_all, preset);

        // JSON bodies stay JSON, HTML keeps its tags.
        for e in v["log"]["entries"].as_array().unwrap() {
            let req = e["request"]["postData"]["text"].as_str().unwrap_or("");
            if e["request"]["url"].as_str().unwrap().ends_with("/login") {
                let j: serde_json::Value =
                    serde_json::from_str(req).unwrap_or_else(|err| panic!("{err}: {req}"));
                assert_eq!(j["fields"][0]["name"], "password");
                assert_eq!(j["product"]["name"], "KEEP-WIDGET");
            }
        }
        assert!(
            saz_all.contains("<input name=password value=&lt;token-")
                && saz_all.contains("<meta name=\"csrf-token\" content=\"&lt;token-"),
            "{saz_all}"
        );
        // The same bearer token has the same pseudonym in the header and in the body.
        let hdr = saz_all
            .split("X-Forwarded-Authorization: Bearer ")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();
        assert!(
            hdr.starts_with("<token-") && saz_all.contains(&format!("\"access_token\":\"{hdr}\"")),
            "{hdr}"
        );
        // Integrity headers of changed bodies are gone; the multipart part says UTF-8 now.
        assert!(
            !saz_all.contains("Content-MD5:")
                && !saz_all.contains("ETag:")
                && !saz_all.contains("\nDigest:"),
            "{saz_all}"
        );
        assert!(
            saz_all.contains(
                "Content-Type: text/plain; charset=utf-8\r\n\r\nGrüße password=%3Ctoken-"
            ),
            "{saz_all}"
        );
        // A cut gzip body keeps its decoded beginning.
        assert!(
            saz_all.contains("…<decoding stopped after") && saz_all.contains("line 1 "),
            "{saz_all}"
        );
        // Binary data sent as text is no text.
        assert!(
            saz_all.contains("<binary body removed: 20 bytes text/plain>"),
            "{saz_all}"
        );
        // WebSocket: the inflated messages are scrubbed and written uncompressed, the
        // fragments joined.
        assert!(
            saz_all.contains(r#"{"type":"auth","token":"<token-"#)
                && saz_all.contains(r#"{"password":"<token-"#),
            "{saz_all}"
        );
        assert!(
            saz_all.contains("Fragmented WebSocket messages joined into one frame each: 1"),
            "{saz_all}"
        );
    }
}

#[test]
fn websocket_frames_are_inflated_and_joined() {
    let tmp = tempfile::tempdir().unwrap();
    let cap = Capture::open(tmp.path().join("cap"), Default::default(), true).unwrap();
    let ids = fill(&cap);
    let ws = *ids
        .iter()
        .find(|id| cap.detail(**id).unwrap().summary.kind == SessionKind::WebSocket)
        .unwrap();
    let d = cap.detail(ws).unwrap();
    let (rq, rs) = cap.bodies_of(ws).unwrap();
    let out = Sanitizer::new(SanitizeOptions::preset("gdpr").unwrap()).session(&d, &rq, &rs);
    let b = out.response;
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos + 16 <= b.len() {
        let len = u32::from_le_bytes(b[pos + 12..pos + 16].try_into().unwrap()) as usize;
        frames.push((
            b[pos],
            b[pos + 1],
            b[pos + 2],
            b[pos + 3],
            String::from_utf8_lossy(&b[pos + 16..pos + 16 + len]).into_owned(),
        ));
        pos += 16 + len;
    }
    assert_eq!(pos, b.len());
    // Four single messages, the ping, the joined message; all final, none compressed.
    assert_eq!(frames.len(), 6, "{frames:?}");
    assert!(frames.iter().all(|f| f.2 == 1 && f.3 == 0), "{frames:?}");
    assert!(
        frames[0]
            .4
            .starts_with(r#"{"type":"auth","token":"<token-"#),
        "{frames:?}"
    );
    assert!(
        frames[1]
            .4
            .starts_with(r#"{"type":"auth","token":"<token-"#)
            && frames[1].4 != frames[0].4,
        "context takeover: {frames:?}"
    );
    assert!(frames[2].4.starts_with("password=%3Ctoken-"), "{frames:?}");
    assert!(frames[3].4.contains("secret: <token-"), "{frames:?}");
    assert_eq!((frames[4].1, frames[5].1), (9, 1));
    assert!(
        frames[5].4.starts_with(r#"{"password":"<token-"#),
        "{frames:?}"
    );
}

/// A progress that asks to stop once scrubbing has begun.
struct StopSoon(std::sync::atomic::AtomicUsize);
impl quena_formats::Progress for StopSoon {
    fn cancelled(&self) -> bool {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0
    }
}

#[test]
fn cancellation_stops_inside_a_large_body() {
    let tmp = tempfile::tempdir().unwrap();
    let cap = Capture::open(tmp.path().join("cap"), Default::default(), true).unwrap();
    let mut body = String::new();
    for i in 0..200_000 {
        body.push_str(&format!("line {i} user{i}@example.com token=abc{i}\n"));
    }
    let id = add(
        &cap,
        detail(
            "GET",
            "https://h.test/big",
            &[],
            &[("Content-Type", "text/plain")],
        ),
        b"",
        body.as_bytes(),
    );
    let path = tmp.path().join("x.saz");
    let t0 = std::time::Instant::now();
    let r = sanitized_export(
        &cap,
        &[id],
        &path,
        ArchiveFormat::Saz,
        SanitizeOptions::default(),
        &tmp.path().join("tmp"),
        Default::default(),
        &StopSoon(Default::default()),
    );
    assert!(r.is_err_and(|e| e.to_string().contains("cancelled")));
    assert!(!path.exists());
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t0.elapsed()
    );
}

/// A log of 100 000 lines with findings on every line.
fn big_log() -> String {
    let mut s = String::with_capacity(12 << 20);
    for i in 0..100_000 {
        s.push_str(&format!("2026-01-01 10:00:{:02} INFO user{i}@example.com from 10.0.{}.{} token=abc{i}def order {i} https://h.example/p?id={i}&session=S{i}\n", i % 60, i % 250, i % 200));
    }
    s
}

fn time_big(preset: &str) -> std::time::Duration {
    let tmp = tempfile::tempdir().unwrap();
    let st = quena_body::BodyStore::open(tmp.path(), Default::default()).unwrap();
    let body = big_log();
    let d = detail(
        "GET",
        "https://h.test/log",
        &[],
        &[("Content-Type", "text/plain")],
    );
    let mut z = Sanitizer::new(SanitizeOptions::preset(preset).unwrap());
    let t0 = std::time::Instant::now();
    let out = z.session(
        &d,
        &quena_body::Body::empty(),
        &st.store_bytes(body.as_bytes()),
    );
    let t = t0.elapsed();
    let text = String::from_utf8(out.response).unwrap();
    assert!(!text.contains("user7@example.com") && !text.contains("S99999"));
    t
}

#[test]
fn large_bodies_take_linear_time() {
    // A sanity bound for unoptimized test builds (the old quadratic span check took minutes).
    let t = time_big("support");
    assert!(
        t < std::time::Duration::from_secs(if cfg!(debug_assertions) { 30 } else { 3 }),
        "{t:?}"
    );
}

#[test]
#[ignore = "timing; run with --release -- --ignored"]
fn large_bodies_release_timing() {
    let t = time_big("support");
    eprintln!("100k lines: {t:?}");
    // About 1.4 s on an M-series Mac in release (3.5 s unoptimized).
    if !cfg!(debug_assertions) {
        assert!(t < std::time::Duration::from_secs(2), "{t:?}");
    }
}
