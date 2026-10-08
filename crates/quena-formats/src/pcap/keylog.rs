//! TLS secrets in the NSS key log format, as written by browsers, curl and other clients
//! with `SSLKEYLOGFILE`, and embedded in pcapng files by Wireshark (Decryption Secrets
//! Block). One line per secret: `<LABEL> <client random hex> <secret hex>`.

use std::collections::HashMap;

/// The secrets of one TLS connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    /// TLS 1.2 and earlier: the master secret (`CLIENT_RANDOM`).
    pub master: Option<Vec<u8>>,
    /// TLS 1.3 handshake traffic secrets (client, server).
    pub handshake: [Option<Vec<u8>>; 2],
    /// TLS 1.3 first application traffic secrets (client, server).
    pub traffic: [Option<Vec<u8>>; 2],
}

/// Secrets by client random.
#[derive(Debug, Clone, Default)]
pub struct KeyLog {
    by_random: HashMap<[u8; 32], Secrets>,
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl KeyLog {
    /// Read key log lines; comments, unknown labels and broken lines are skipped.
    pub fn parse(text: &[u8]) -> KeyLog {
        let mut k = KeyLog::default();
        k.add(text);
        k
    }

    /// Add the lines of another key log.
    pub fn add(&mut self, text: &[u8]) {
        for line in String::from_utf8_lossy(text).lines() {
            let mut p = line.split_ascii_whitespace();
            let (Some(label), Some(random), Some(secret), None) =
                (p.next(), p.next(), p.next(), p.next())
            else {
                continue;
            };
            let (Some(random), Some(secret)) = (hex(random), hex(secret)) else {
                continue;
            };
            let Ok(random) = <[u8; 32]>::try_from(random.as_slice()) else {
                continue;
            };
            let slot = match label {
                "CLIENT_RANDOM" => {
                    self.by_random.entry(random).or_default().master = Some(secret);
                    continue;
                }
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => (0, true),
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => (1, true),
                "CLIENT_TRAFFIC_SECRET_0" => (0, false),
                "SERVER_TRAFFIC_SECRET_0" => (1, false),
                _ => continue,
            };
            let s = self.by_random.entry(random).or_default();
            let list = if slot.1 {
                &mut s.handshake
            } else {
                &mut s.traffic
            };
            list[slot.0] = Some(secret);
        }
    }

    pub fn get(&self, client_random: &[u8; 32]) -> Option<&Secrets> {
        self.by_random.get(client_random)
    }

    pub fn len(&self) -> usize {
        self.by_random.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_random.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nss_key_log() {
        let r1 = "01".repeat(32);
        let r2 = "02".repeat(32);
        let text = format!(
            "# SSL/TLS secrets log file\n\
             CLIENT_RANDOM {r1} {}\n\
             CLIENT_HANDSHAKE_TRAFFIC_SECRET {r2} aabb\r\n\
             SERVER_TRAFFIC_SECRET_0 {r2} ccdd\n\
             EXPORTER_SECRET {r2} eeff\n\
             CLIENT_RANDOM 0102 0304\n\
             CLIENT_RANDOM {r1} zz\n",
            "ab".repeat(48)
        );
        let k = KeyLog::parse(text.as_bytes());
        assert_eq!(k.len(), 2);
        assert_eq!(
            k.get(&[1; 32]).unwrap().master.as_deref(),
            Some(&[0xab; 48][..])
        );
        let s = k.get(&[2; 32]).unwrap();
        assert_eq!(s.handshake[0].as_deref(), Some(&[0xaa, 0xbb][..]));
        assert_eq!(s.traffic[1].as_deref(), Some(&[0xcc, 0xdd][..]));
        assert!(s.master.is_none() && s.traffic[0].is_none());
    }
}
