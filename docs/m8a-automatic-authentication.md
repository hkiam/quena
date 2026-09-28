# M8a – Automatic Authentication (Umsetzungsplan)

> Detailplan zu `PLAN.md` §2.14. Fiddler-Feature „Enable Automatic Authentication“:
> Piper beantwortet `401`/`407`-Challenges selbst mit den Zugangsdaten des Entwicklers,
> damit man beim Debuggen nicht bei jedem Request manuell einloggen muss.
> Standardmäßig **aus**, opt-in pro Host empfohlen.

## 1. Ziel und Abgrenzung

Wenn ein Server `401 Unauthorized` (`WWW-Authenticate`) oder ein vorgeschalteter
Firmenproxy `407 Proxy Authentication Required` (`Proxy-Authenticate`) liefert und
das Schema von Piper unterstützt wird, führt Piper den Auth-Handshake transparent
durch und liefert dem Client die fertige, authentifizierte Antwort. Die einzelnen
Handshake-Legs werden in der Session-Liste sichtbar gemacht (wie in Fiddler).

**Erste Ausbaustufe (macOS zuerst):**
- **Basic** – trivial, Base64 `user:pass` aus dem Credential Store.
- **NTLM (NTLMv2)** – reines Rust, Zugangsdaten aus der Keychain (macOS speichert
  keine wiederverwendbaren NTLM-Hashes des Benutzers → kein echtes SSO).
- **Negotiate/Kerberos (SPNEGO)** – SSO über GSS.framework, wenn ein Kerberos-Ticket
  vorhanden ist (AD-gebunden, Enterprise-SSO-Extension oder `kinit`).

**Später mit dem Windows-Port (M13):** echtes SSO für NTLM *und* Negotiate über
SSPI (`InitializeSecurityContextW`) mit dem angemeldeten Windows-Benutzer.

## 2. Nicht-verhandelbare Sicherheitsregeln

1. Feature ist **opt-in** (Default aus); Host-Allowlist empfohlen.
2. Zugangsdaten kommen **nur** aus dem OS-Secure-Store (Keychain / Credential Manager),
   werden vom Benutzer eingegeben und nur für dessen eigene Debug-Session verwendet.
   Niemals in `settings.json`, niemals im Klartext, niemals im Log.
3. `Authorization` / `Proxy-Authorization` und alle Auth-Tokens werden in Logs redigiert.
4. **Verbindungs-Pinning**: NTLM/Negotiate authentifizieren die TCP-Verbindung, nicht
   den Request. Eine authentifizierte Upstream-Verbindung darf **niemals** an eine
   andere Client-Verbindung vererbt werden (sonst spräche Client B unter der Identität
   von Client A). Siehe §5.

## 3. Neues Crate `piper-auth`

Schema-unabhängige Engine, keine Netzwerk- oder Proxy-Abhängigkeit (testbar isoliert).

```rust
/// Ein Schema in Aktion (ein Handshake).
pub trait AuthScheme: Send {
    /// Nächster Token für den `Authorization`/`Proxy-Authorization`-Header.
    /// `challenge` = Token aus der Server-Challenge (None beim ersten Aufruf).
    fn step(&mut self, challenge: Option<&[u8]>) -> Result<Vec<u8>, AuthError>;
    fn is_complete(&self) -> bool;
    fn header_scheme(&self) -> &'static str; // "NTLM" | "Negotiate" | "Basic"
}

pub enum Scheme { Basic, Ntlm, Negotiate }

/// `WWW-Authenticate` / `Proxy-Authenticate` parsen → angebotene Schemata + Token.
pub fn parse_challenges(header_values: &[&str]) -> Vec<Offer>;
pub struct Offer { pub scheme: Scheme, pub token: Option<Vec<u8>>, pub params: Vec<(String,String)> }
```

Auswahl: stärkstes unterstütztes Schema in der Reihenfolge Negotiate > NTLM > Basic
(konfigurierbar über `AuthSettings.prefer`).

### 3.1 Krypto ohne fremde Versions-Kopplung

MD4, MD5, HMAC-MD5 werden **selbst implementiert** (wie schon SHA-1 für den
CA-Fingerprint in `piper-tls`). Grund: die `digest`-Versionsketten von `md4`/`md-5`/
`hmac` kollidieren leicht, und die Algorithmen sind klein. Das hält den
Abhängigkeitsbaum permissiv und stabil. Modul `piper-auth::crypto`.

### 3.2 NTLMv2 (MS-NLMP)

- **Type 1 (Negotiate)**: feste Flags (Unicode, NTLM, Always Sign, Target Info,
  Extended Session Security), Workstation/Domain leer.
- **Type 2 (Challenge)**: aus `WWW-Authenticate: NTLM <base64>` parsen –
  Server-Challenge (8 Byte), Target Info (AV_PAIRs), Flags.
- **Type 3 (Authenticate)**: NTLMv2-Response berechnen:
  - `NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UPPER(user) ++ domain)`
  - `blob = 0x01010000 ++ 0 ++ timestamp ++ client_challenge(8) ++ 0 ++ target_info ++ 0`
  - `NTProofStr = HMAC_MD5(NTOWFv2, server_challenge ++ blob)`
  - `NtChallengeResponse = NTProofStr ++ blob`
  - Session-Key / MIC nur wenn nötig (die meisten Server verlangen keinen MIC beim
    reinen Proxy-Durchlauf; MIC-Berechnung als optionaler Schritt vorsehen).
- **Known-Answer-Tests** aus MS-NLMP §4.2.4 (veröffentlichte Vektoren) als Unit-Test.

### 3.3 Negotiate/Kerberos (SPNEGO, macOS)

- GSS.framework über GSS-API-C-Bindings (`gss_init_sec_context` mit SPNEGO-Mech-OID).
- Ziel-SPN: `HTTP@<host>` (bzw. `HTTP/<host>`).
- SSO mit vorhandenem Ticket; kein Ticket → `AuthError::NoCredentials` → Fallback
  auf NTLM/Basic oder UI-Prompt.
- Framework-Link: `#[link(name = "GSS", kind = "framework")]`, nur `cfg(target_os="macos")`.
- SPNEGO-Token-Wrapping isoliert unit-testbar; der volle Handshake braucht ein KDC
  → als manueller/optionaler Test markiert.

## 4. Credential Store (`PlatformServices::secure_store`)

Neuer Trait-Teil in `piper-platform`:

```rust
pub trait SecureStore {
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<()>;
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, service: &str, account: &str) -> Result<()>;
    fn list(&self, service: &str) -> Result<Vec<String>>;
}
```

- **macOS**: Keychain über das `security`-CLI (`add-generic-password -U`,
  `find-generic-password -w`, `delete-generic-password`), Service `io.github.hkiam.piper.auth`,
  Account = `realm|host|user`. Konsistent mit der bestehenden CA-Trust-Nutzung von `security`.
- **Windows**: Credential Manager (`CredWriteW`/`CredReadW`) – mit M13.
- **Linux**: Secret Service (libsecret) optional; sonst nur In-Memory für die Session.

## 5. Verbindungs-Pinning in `piper-proxy`

Kernstück und die eigentliche Architekturänderung.

**Problem:** Der `hyper_util`-Legacy-Client poolt Upstream-Verbindungen pro Host und
teilt sie über alle Client-Verbindungen. Für verbindungsgebundene Auth ist das falsch.

**Design `AuthBoundConn`:**
- Wird für einen Host Auto-Auth ausgelöst, verlässt dieser Request den geteilten Pool.
- Piper öffnet eine **dedizierte** Upstream-Verbindung, betreibt darauf den Handshake
  und **pinnt** sie an `(client_conn_id, host, port)` für die restliche Lebensdauer
  der Client-Verbindung. Map `HashMap<(u64,String,u16), PinnedConn>` in `Shared`.
- Folge-Requests derselben Client-Verbindung an denselben Host laufen über diese
  gepinnte Verbindung (kein Pool, kein Vererben an andere Clients).
- Aufräumen: wenn die Client-Verbindung schließt, werden ihre gepinnten Upstreams
  geschlossen.

**Request-Body-Replay:** Für jeden Handshake-Leg muss der Request-Body erneut
gesendet werden → Body wird über den Body-Store gepuffert (Spill-to-Disk für große
Bodies, existiert bereits). Reuse der Interceptor-Buffer-Logik.

**Einbau:** neue Funktion `send_upstream_with_auth(...)` als Wrapper um `send_upstream`:

```text
send_upstream_with_auth:
  resp = send_upstream(head, body)                 // ggf. auf dedizierter Conn
  loop, solange resp == 401/407 und Auto-Auth für host aktiv und Schema unterstützt:
     scheme = pick(parse_challenges(resp.headers))
     token  = scheme.step(challenge_from(resp))
     head'  = head + Authorization/Proxy-Authorization: <scheme> base64(token)
     resp   = send_upstream(head', body_replay)    // SELBE gepinnte Conn
     record handshake-leg als Kind-Session
  return resp
```

- `401` → `WWW-Authenticate` / `Authorization`.
- `407` → `Proxy-Authenticate` / `Proxy-Authorization`, gegen den **Upstream-Proxy**
  (im Firmenumfeld der wichtigste Fall). Hier ist die gepinnte Verbindung die
  Verbindung zum Firmenproxy.
- Endlosschutz: max. 5 Legs, danach Original-`401`/`407` durchreichen.

## 6. Konfiguration (`AuthSettings`)

```rust
pub struct AuthSettings {
    pub enabled: bool,                 // Rules → Enable Automatic Authentication
    pub hosts: String,                 // Allowlist (leer = alle), ";"-getrennt, Wildcards
    pub upstream_auth: bool,           // 407 vom Firmenproxy behandeln
    pub prefer: Vec<Scheme>,           // Default [Negotiate, Ntlm, Basic]
    pub use_current_identity: bool,    // SSO (Kerberos/SSPI) bevorzugen
    // Zugangsdaten NICHT hier – nur Referenzen; Secrets im Secure Store.
    pub credentials: Vec<CredRef>,     // { host/realm, user } – Passwort in Keychain
}
```

## 7. UI

- **Rules-Menü:** „Enable Automatic Authentication“ (Checkbox), gebunden an `enabled`.
- **Options → Authentication** (neuer Tab): enabled, Host-Allowlist, „Handle upstream
  proxy (407)“, Schema-Reihenfolge, „Use current OS identity (SSO)“, Button
  „Manage credentials…“.
- **Credential-Manager-Dialog:** Liste Host/Realm + User; Hinzufügen (User+Passwort →
  Keychain), Entfernen. Passwortfeld nie zurücklesen.
- **Handshake-Sichtbarkeit:** Legs als Kind-Sessions mit Flag `AUTH`; im Original steht
  „authenticated (N legs)“. Spalte/Icon wie bei Replay.
- **Statusleiste:** `EngineStatus.auth_active` → kleines Kürzel wie bei AutoResponder.

## 8. Teststrategie

- **NTLMv2 KAT:** MS-NLMP §4.2.4 Vektoren (User `User`, Domain `Domain`, Passwort
  `Password`, feste Challenges) → `NtChallengeResponse` byte-genau.
- **Header-Parser:** mehrere `WWW-Authenticate`-Zeilen, gemischte Schemata,
  Groß/Kleinschreibung, Token mit/ohne `=` Padding.
- **Lokaler NTLM-Testserver** (im Test): fordert `WWW-Authenticate: NTLM`, validiert
  Type-1/Type-3, antwortet 200. Piper muss den Handshake abschließen; UI zeigt 200 +
  Legs. Reines Rust, kein AD nötig.
- **Basic:** gegen `/basic-auth/user/pass`-artigen Testserver.
- **Sicherheits-Test Pinning:** zwei nebenläufige Clients an denselben Auth-Host →
  keine geteilte Auth; Client B bekommt eine eigene `401`, nicht die Identität von A.
- **407:** Testserver als Upstream-Proxy mit `Proxy-Authenticate: NTLM`.
- **Kerberos/GSS:** SPNEGO-Wrapping unit-getestet; voller Flow manuell gegen ein KDC.

## 9. Schritte / Reihenfolge

| Schritt | Inhalt | Test |
|---|---|---|
| M8a.1 | `piper-auth`: crypto (MD4/MD5/HMAC-MD5), Header-Parser, Basic, NTLMv2 | KAT + Parser-Unit-Tests |
| M8a.2 | `SecureStore` (macOS Keychain) in `piper-platform` | Roundtrip-Test (temp. Service) |
| M8a.3 | Verbindungs-Pinning + `send_upstream_with_auth` (Server-401, NTLM/Basic) | lokaler NTLM-Testserver, e2e |
| M8a.4 | Upstream-`407` behandeln | Proxy-Testserver |
| M8a.5 | Negotiate/Kerberos via GSS.framework (macOS) | SPNEGO-Wrapping-Unit; KDC manuell |
| M8a.6 | UI: Rules-Menü, Options-Tab, Credential-Manager, Handshake-Sessions | manueller UI-Test |
| M8a.7 | Windows-SSPI (mit M13): SSO NTLM + Negotiate | Windows-CI |

## 10. Definition of Done (M8a)

- Auto-Auth global und pro Host aktivierbar, Default aus.
- Basic + NTLMv2 gegen Test-Server erfolgreich; UI zeigt finale 200 + Handshake-Legs.
- `407` gegen Firmenproxy erfolgreich.
- Zwei Clients an denselben Host teilen keinen Auth-Zustand (Pinning bewiesen).
- Zugangsdaten ausschließlich in der Keychain; keine Klartext-Persistenz; Logs redigiert.
- Kerberos-SSO funktioniert, wenn ein Ticket vorhanden ist (macOS).
- NTLMv2-KAT grün.
