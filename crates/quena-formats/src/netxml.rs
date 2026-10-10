//! Internet Explorer's F12 network capture as XML ("NetXML"): the HAR structure written as
//! XML elements. Turned into HAR and imported as such.

use crate::{FormatError, Progress, Result};
use quick_xml::events::Event;
use quena_model::SessionId;
use quena_store::Capture;
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::Arc;

/// Elements whose children form a list.
const LISTS: &[&str] = &["entries", "pages", "headers", "cookies", "queryString", "params"];
/// Leaves that are numbers in HAR.
const NUMBERS: &[&str] = &["status", "time", "size", "bodySize", "headersSize", "send", "wait", "receive", "blocked", "dns", "connect", "ssl", "compression", "onContentLoad", "onLoad"];

struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

fn to_json(n: &Node) -> Value {
    if LISTS.contains(&n.name.as_str()) {
        return Value::Array(n.children.iter().map(to_json).collect());
    }
    if n.children.is_empty() {
        let t = n.text.trim();
        if NUMBERS.contains(&n.name.as_str())
            && let Ok(v) = t.parse::<f64>()
        {
            // Whole numbers as integers (a status is an integer in HAR).
            return if v.fract() == 0.0 && v.abs() < 9e15 { serde_json::json!(v as i64) } else { serde_json::json!(v) };
        }
        // Body text keeps its spacing.
        return Value::String(if n.name == "text" { n.text.clone() } else { t.to_string() });
    }
    let mut m = Map::new();
    for c in &n.children {
        m.insert(c.name.clone(), to_json(c));
    }
    Value::Object(m)
}

/// The NetXML document as a HAR object (`{"log": …}`).
pub fn to_har(xml: &str) -> Result<Value> {
    let mut r = quick_xml::Reader::from_str(xml);
    let mut stack: Vec<Node> = vec![Node { name: String::new(), text: String::new(), children: vec![] }];
    loop {
        match r.read_event().map_err(|e| FormatError::Invalid(format!("NetXML: {e}")))? {
            Event::Start(e) => stack.push(Node { name: String::from_utf8_lossy(e.local_name().as_ref()).into_owned(), text: String::new(), children: vec![] }),
            Event::Empty(e) => {
                let n = Node { name: String::from_utf8_lossy(e.local_name().as_ref()).into_owned(), text: String::new(), children: vec![] };
                if let Some(top) = stack.last_mut() {
                    top.children.push(n);
                }
            }
            Event::Text(t) => {
                let s = t.decode().map_err(|e| FormatError::Invalid(format!("NetXML: {e}")))?;
                let s = quick_xml::escape::unescape(&s).map_err(|e| FormatError::Invalid(format!("NetXML: {e}")))?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&s);
                }
            }
            Event::CData(t) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(&t));
                }
            }
            Event::GeneralRef(e) => {
                let name = String::from_utf8_lossy(&e).into_owned();
                let ch = match name.as_str() {
                    "amp" => "&".to_string(),
                    "lt" => "<".to_string(),
                    "gt" => ">".to_string(),
                    "quot" => "\"".to_string(),
                    "apos" => "'".to_string(),
                    n if n.starts_with("#x") => u32::from_str_radix(&n[2..], 16).ok().and_then(char::from_u32).map(String::from).unwrap_or_default(),
                    n if n.starts_with('#') => n[1..].parse::<u32>().ok().and_then(char::from_u32).map(String::from).unwrap_or_default(),
                    _ => String::new(),
                };
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&ch);
                }
            }
            Event::End(_) => {
                let n = stack.pop().ok_or_else(|| FormatError::Invalid("NetXML: unbalanced elements".into()))?;
                stack.last_mut().ok_or_else(|| FormatError::Invalid("NetXML: unbalanced elements".into()))?.children.push(n);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let root = stack.pop().and_then(|r| r.children.into_iter().find(|c| c.name == "log")).ok_or_else(|| FormatError::Invalid("not an IE NetXML capture (no <log>)".into()))?;
    Ok(serde_json::json!({ "log": to_json(&root) }))
}

/// Import an IE NetXML capture.
pub fn import(cap: &Arc<Capture>, path: &Path, p: &dyn Progress) -> Result<Vec<SessionId>> {
    let xml = std::fs::read_to_string(path)?;
    let har = to_har(xml.trim_start_matches('\u{feff}'))?;
    let tmp = path.with_extension("netxml-har.part");
    let tmp = std::env::temp_dir().join(tmp.file_name().unwrap_or_default());
    std::fs::write(&tmp, serde_json::to_vec(&har)?)?;
    let r = crate::har::import(cap, &tmp, p);
    let _ = std::fs::remove_file(&tmp);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netxml_becomes_har() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<log><version>1.1</version><creator><name>Internet Explorer Network Inspector</name><version>9.0</version></creator>
<entries><entry><startedDateTime>2011-07-12T09:28:34.316+02:00</startedDateTime><time>187</time>
<request><method>POST</method><url>http://www.example.com/a?x=1</url><httpVersion>HTTP/1.1</httpVersion><cookies/>
<headers><header><name>Accept</name><value>text/html</value></header><header><name>Content-Type</name><value>text/plain</value></header></headers>
<queryString><param><name>x</name><value>1</value></param></queryString><postData><mimeType>text/plain</mimeType><text>a &amp; b</text></postData><headersSize>401</headersSize><bodySize>5</bodySize></request>
<response><status>200</status><statusText>OK</statusText><httpVersion>HTTP/1.1</httpVersion><cookies/><headers><header><name>Content-Type</name><value>text/html</value></header></headers>
<content><size>12</size><mimeType>text/html</mimeType><text><![CDATA[<p>Hi</p>]]></text></content><redirectURL/><headersSize>100</headersSize><bodySize>12</bodySize></response>
<cache/><timings><send>0</send><wait>150</wait><receive>37</receive></timings></entry></entries></log>"#;
        let h = to_har(xml).unwrap();
        let e = &h["log"]["entries"][0];
        assert_eq!(e["request"]["method"], "POST");
        assert_eq!(e["request"]["headers"][1]["value"], "text/plain");
        assert_eq!(e["request"]["postData"]["text"], "a & b");
        assert_eq!(e["response"]["status"], 200);
        assert_eq!(e["response"]["content"]["text"], "<p>Hi</p>");
        assert_eq!(e["timings"]["wait"], 150);
        assert!(to_har("<html/>").is_err());
    }
}
