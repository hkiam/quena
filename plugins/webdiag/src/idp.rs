//! Identity provider knowledge: which IdP serves an endpoint, what its error codes mean,
//! and where an administrator fixes the cause.
//!
//! * [`detect`] / [`from_issuer`]: Microsoft Entra ID (incl. B2C and External ID), AD FS,
//!   Keycloak, Okta, Auth0, Amazon Cognito, Google, Duende IdentityServer, PingFederate, or a
//!   generic OpenID Connect provider.
//! * [`endpoint`]: the kind of an OAuth/OIDC endpoint from its path.
//! * [`aadsts`], [`oauth_error`], [`keycloak`]: explanations of Entra ID `AADSTS` codes,
//!   the standard OAuth 2 / OIDC / device flow / DPoP error codes and Keycloak's
//!   `error_description` texts — cause and remedy in both report languages, plus the
//!   [`Topic`] that says where the remedy is configured.
//! * [`where_to`]: the place in the admin UI (or configuration) of an IdP for a topic.
//!   Menu paths are the English UI names in both languages.
//! * [`resource_cause`]: the cause behind a resource server's `error_description`
//!   (ASP.NET Core `IDX…` messages and similar texts).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Idp {
    Entra,
    EntraB2c,
    EntraExternal,
    Adfs,
    Keycloak,
    Okta,
    Auth0,
    Cognito,
    Google,
    Duende,
    Ping,
    Generic,
}

impl Idp {
    pub fn name(self) -> &'static str {
        match self {
            Idp::Entra => "Microsoft Entra ID",
            Idp::EntraB2c => "Azure AD B2C",
            Idp::EntraExternal => "Microsoft Entra External ID",
            Idp::Adfs => "AD FS",
            Idp::Keycloak => "Keycloak",
            Idp::Okta => "Okta",
            Idp::Auth0 => "Auth0",
            Idp::Cognito => "Amazon Cognito",
            Idp::Google => "Google",
            Idp::Duende => "Duende IdentityServer",
            Idp::Ping => "PingFederate",
            Idp::Generic => "OpenID Connect",
        }
    }
    /// Entra ID family: AADSTS codes apply.
    pub fn is_entra(self) -> bool {
        matches!(self, Idp::Entra | Idp::EntraB2c | Idp::EntraExternal)
    }
}

fn host_only(host: &str) -> &str {
    let h = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    h.trim_end_matches('.')
}

fn ends(h: &str, suffix: &str) -> bool {
    h.len() >= suffix.len() && h[h.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Entra ID sign-in hosts (all clouds) and the v1 issuer host.
const ENTRA_HOSTS: [&str; 8] = [
    "login.microsoftonline.com",
    "login.windows.net",
    "login.microsoft.com",
    "sts.windows.net",
    "login.microsoftonline.us",
    "login.chinacloudapi.cn",
    "login.partner.microsoftonline.cn",
    "login.microsoftonline.de",
];

/// The identity provider of a host, from the host name alone.
pub fn by_host(host: &str) -> Option<Idp> {
    let h = host_only(host);
    if ENTRA_HOSTS.iter().any(|x| h.eq_ignore_ascii_case(x)) {
        return Some(Idp::Entra);
    }
    if ends(h, ".b2clogin.com") || ends(h, ".b2clogin.cn") {
        return Some(Idp::EntraB2c);
    }
    if ends(h, ".ciamlogin.com") {
        return Some(Idp::EntraExternal);
    }
    if ends(h, ".okta.com") || ends(h, ".oktapreview.com") || ends(h, ".okta-emea.com") || ends(h, ".okta-gov.com") {
        return Some(Idp::Okta);
    }
    if ends(h, ".auth0.com") {
        return Some(Idp::Auth0);
    }
    if ends(h, ".amazoncognito.com") || (h.len() > 12 && h[..12].eq_ignore_ascii_case("cognito-idp.") && ends(h, ".amazonaws.com")) {
        return Some(Idp::Cognito);
    }
    if h.eq_ignore_ascii_case("accounts.google.com") || h.eq_ignore_ascii_case("oauth2.googleapis.com") {
        return Some(Idp::Google);
    }
    if ends(h, ".pingone.com") || ends(h, ".pingone.eu") || ends(h, ".pingidentity.com") {
        return Some(Idp::Ping);
    }
    None
}

fn path_has(path: &str, needle: &str) -> bool {
    path.len() >= needle.len() && path.as_bytes().windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// The identity provider serving `path` on `host`, if the host or the path is recognised.
/// `None` for paths that are not IdP endpoints on unknown hosts.
pub fn detect(host: &str, path: &str) -> Option<Idp> {
    if let Some(i) = by_host(host) {
        return Some(i);
    }
    if path_has(path, "/adfs/") {
        return Some(Idp::Adfs);
    }
    if path_has(path, "/realms/") && (path_has(path, "/protocol/openid-connect") || path_has(path, "/.well-known/")) {
        return Some(Idp::Keycloak);
    }
    if path_has(path, "/as/token.oauth2") || path_has(path, "/as/authorization.oauth2") || path_has(path, "/pf/jwks") {
        return Some(Idp::Ping);
    }
    if path_has(path, "/connect/token")
        || path_has(path, "/connect/authorize")
        || path_has(path, "/connect/deviceauthorization")
        || path_has(path, "/connect/endsession")
        || path_has(path, "/.well-known/openid-configuration/jwks")
    {
        return Some(Idp::Duende);
    }
    match endpoint(path) {
        Endpoint::Other => None,
        _ => Some(Idp::Generic),
    }
}

/// The identity provider that issued a token (`iss` claim or discovery `issuer`).
pub fn from_issuer(iss: &str) -> Idp {
    let u = crate::canon::parse(iss);
    if by_host(&u.host).is_none() && path_has(&u.path, "/realms/") {
        return Idp::Keycloak;
    }
    detect(&u.host, &u.path).unwrap_or(Idp::Generic)
}

/// Entra ID v1 issuer (`https://sts.windows.net/<tid>/`); v2 is `login.microsoftonline.com/<tid>/v2.0`.
pub fn is_entra_v1_issuer(iss: &str) -> bool {
    path_has(iss, "sts.windows.net/")
}

/// Keycloak realm or Entra ID tenant (first path segment) of an IdP URL path.
pub fn tenant_or_realm(idp: Idp, path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match idp {
        Idp::Keycloak => segs.iter().position(|s| s.eq_ignore_ascii_case("realms")).and_then(|i| segs.get(i + 1)).map(|s| s.to_string()),
        Idp::Entra | Idp::EntraExternal | Idp::EntraB2c => {
            segs.first().filter(|s| !s.starts_with('.') && !s.eq_ignore_ascii_case("oauth2") && !s.eq_ignore_ascii_case("error")).map(|s| s.to_string())
        }
        _ => None,
    }
}

// ------------------------------------------------------------------ endpoints

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Endpoint {
    Authorize,
    Token,
    Device,
    Discovery,
    Jwks,
    Userinfo,
    Introspect,
    Revoke,
    Logout,
    Other,
}

impl Endpoint {
    pub fn label(self) -> &'static str {
        match self {
            Endpoint::Authorize => "authorize",
            Endpoint::Token => "token",
            Endpoint::Device => "device authorization",
            Endpoint::Discovery => "discovery",
            Endpoint::Jwks => "JWKS",
            Endpoint::Userinfo => "userinfo",
            Endpoint::Introspect => "introspection",
            Endpoint::Revoke => "revocation",
            Endpoint::Logout => "logout",
            Endpoint::Other => "resource",
        }
    }
}

/// The kind of an OAuth/OIDC endpoint from its URL path (case-insensitive).
pub fn endpoint(path: &str) -> Endpoint {
    let p = path.trim_end_matches('/');
    // Fast rejection on the last segment (this runs for every session of a capture).
    const LAST: [&str; 25] = [
        "token", "token.oauth2", "access_token", "devicecode", "code", "device", "deviceauthorization", "authorize", "device_authorization", "introspect", "introspection", "revoke",
        "revocation", "auth", "authorization.oauth2", "openid-configuration", "oauth-authorization-server", "keys", "certs", "jwks.json", "jwks", "userinfo", "logout", "endsession",
        "end_session",
    ];
    let last = p.rsplit('/').next().unwrap_or("");
    if !LAST.iter().any(|l| last.eq_ignore_ascii_case(l)) {
        return Endpoint::Other;
    }
    let e = |s: &str| ends(p, s);
    if e("/.well-known/openid-configuration") || e("/.well-known/oauth-authorization-server") {
        Endpoint::Discovery
    } else if e("/devicecode")
        || e("/device/code")
        || e("/openid-connect/auth/device")
        || e("/connect/deviceauthorization")
        || e("/device/authorize")
        || e("/device_authorization")
        || e("/oauth2/deviceauthorization")
    {
        Endpoint::Device
    } else if e("/introspect") || e("/token/introspect") || e("/introspection") {
        Endpoint::Introspect
    } else if e("/revoke") || e("/revocation") || e("/token/revoke") {
        Endpoint::Revoke
    } else if e("/token") || e("/token.oauth2") || e("/access_token") {
        Endpoint::Token
    } else if e("/authorize") || e("/openid-connect/auth") || e("/authorization.oauth2") || e("/o/oauth2/v2/auth") || e("/o/oauth2/auth") || e("/oauth2/auth") {
        Endpoint::Authorize
    } else if e("/discovery/keys")
        || e("/discovery/v2.0/keys")
        || e("/openid-connect/certs")
        || e("/.well-known/jwks.json")
        || e("/.well-known/jwks")
        || e("/openid-configuration/jwks")
        || e("/oauth2/v1/keys")
        || e("/v1/keys")
        || e("/oauth2/v3/certs")
        || e("/pf/jwks")
        || e("/jwks")
    {
        Endpoint::Jwks
    } else if e("/userinfo") || e("/openid-connect/userinfo") || e("/oauth2/v3/userinfo") {
        Endpoint::Userinfo
    } else if e("/logout") || e("/endsession") || e("/end_session") || e("/openid-connect/logout") || e("/oauth2/v2.0/logout") {
        Endpoint::Logout
    } else {
        Endpoint::Other
    }
}

// ------------------------------------------------------------------ where to fix

/// Where a remedy is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    RedirectUri,
    ClientCredentials,
    Consent,
    Flows,
    Pkce,
    Lifetime,
    Audience,
    Cors,
    Logs,
    Groups,
    SilentRenew,
    AccessPolicy,
    Assignment,
    Tenant,
}

/// The place in the IdP's admin UI or configuration for `topic`, as `(en, de)`.
/// Both keep the admin UI's English labels and navigation paths (admins search
/// for them) as well as config/API identifiers; only the explanatory prose is
/// translated. Callers pick the language with `ctx.l` / `pick`.
pub fn where_to(idp: Idp, topic: Topic) -> Option<(&'static str, &'static str)> {
    use Idp::*;
    use Topic::*;
    Some(match (topic, idp) {
        (RedirectUri, Entra | EntraExternal) => (
            "App registrations → <app> → Authentication → Platform configurations → Redirect URIs (exact match incl. scheme, port, path and trailing slash; Web vs. Single-page application platform)",
            "App registrations → <app> → Authentication → Platform configurations → Redirect URIs (exakte Übereinstimmung inkl. Schema, Port, Pfad und abschließendem Schrägstrich; Plattform Web vs. Single-page application)",
        ),
        (RedirectUri, EntraB2c) => ("Azure AD B2C → App registrations → <app> → Authentication → Redirect URIs", "Azure AD B2C → App registrations → <app> → Authentication → Redirect URIs"),
        (RedirectUri, Keycloak) => (
            "Clients → <client> → Settings → Valid redirect URIs (and Valid post logout redirect URIs)",
            "Clients → <client> → Settings → Valid redirect URIs (und Valid post logout redirect URIs)",
        ),
        (RedirectUri, Okta) => ("Applications → <app> → General → Login → Sign-in redirect URIs", "Applications → <app> → General → Login → Sign-in redirect URIs"),
        (RedirectUri, Auth0) => ("Applications → <app> → Settings → Allowed Callback URLs", "Applications → <app> → Settings → Allowed Callback URLs"),
        (RedirectUri, Cognito) => (
            "User pool → App integration → App clients → <client> → Login pages → Allowed callback URLs",
            "User pool → App integration → App clients → <client> → Login pages → Allowed callback URLs",
        ),
        (RedirectUri, Google) => (
            "Google Cloud console → APIs & Services → Credentials → <OAuth client> → Authorized redirect URIs",
            "Google Cloud console → APIs & Services → Credentials → <OAuth client> → Authorized redirect URIs",
        ),
        (RedirectUri, Adfs) => (
            "AD FS Management → Application Groups → <group> → <application> → Redirect URI (Set-AdfsNativeClientApplication / Set-AdfsServerApplication -RedirectUri)",
            "AD FS Management → Application Groups → <group> → <application> → Redirect URI (Set-AdfsNativeClientApplication / Set-AdfsServerApplication -RedirectUri)",
        ),
        (RedirectUri, Duende) => ("Client.RedirectUris in the IdentityServer client configuration", "Client.RedirectUris in der Client-Konfiguration von IdentityServer"),
        (RedirectUri, Ping) => ("Applications → OAuth → Clients → <client> → Redirection URIs", "Applications → OAuth → Clients → <client> → Redirection URIs"),
        (ClientCredentials, Entra | EntraExternal | EntraB2c) => (
            "App registrations → <app> → Certificates & secrets (use the secret's Value, not its Secret ID; check the expiry date)",
            "App registrations → <app> → Certificates & secrets (den Value des Secrets verwenden, nicht die Secret ID; Ablaufdatum prüfen)",
        ),
        (ClientCredentials, Keycloak) => (
            "Clients → <client> → Credentials (Client Authenticator, Client secret); Settings → Client authentication must be On for confidential clients",
            "Clients → <client> → Credentials (Client Authenticator, Client secret); Settings → Client authentication muss bei vertraulichen Clients On sein",
        ),
        (ClientCredentials, Okta) => (
            "Applications → <app> → General → Client Credentials (client authentication method, secrets)",
            "Applications → <app> → General → Client Credentials (Methode der Client-Authentifizierung, Secrets)",
        ),
        (ClientCredentials, Auth0) => ("Applications → <app> → Credentials (Authentication Method, Client Secret)", "Applications → <app> → Credentials (Authentication Method, Client Secret)"),
        (ClientCredentials, Cognito) => (
            "User pool → App integration → App clients → <client> → Client secret (requests must send one exactly when the client has one)",
            "User pool → App integration → App clients → <client> → Client secret (Requests müssen genau dann eines senden, wenn der Client eines hat)",
        ),
        (ClientCredentials, Google) => ("Google Cloud console → Credentials → <OAuth client> → Client secrets", "Google Cloud console → Credentials → <OAuth client> → Client secrets"),
        (ClientCredentials, Adfs) => ("AD FS Management → Application Groups → <server application> → Credentials", "AD FS Management → Application Groups → <server application> → Credentials"),
        (ClientCredentials, Duende) => (
            "Client.ClientSecrets (stored hashed, e.g. \"secret\".Sha256()) and RequireClientSecret",
            "Client.ClientSecrets (gehasht gespeichert, z. B. \"secret\".Sha256()) und RequireClientSecret",
        ),
        (ClientCredentials, Ping) => ("Applications → OAuth → Clients → <client> → Client Authentication", "Applications → OAuth → Clients → <client> → Client Authentication"),
        (Consent, Entra | EntraExternal) => (
            "App registrations → <app> → API permissions → Add a permission → Grant admin consent for <tenant> (Enterprise applications → <app> → Permissions shows what is granted)",
            "App registrations → <app> → API permissions → Add a permission → Grant admin consent for <tenant> (Enterprise applications → <app> → Permissions zeigt, was erteilt ist)",
        ),
        (Consent, EntraB2c) => (
            "Azure AD B2C → App registrations → <app> → API permissions → Grant admin consent",
            "Azure AD B2C → App registrations → <app> → API permissions → Grant admin consent",
        ),
        (Consent, Keycloak) => (
            "Clients → <client> → Client scopes (assigned default/optional scopes) and Settings → Login settings → Consent required",
            "Clients → <client> → Client scopes (zugewiesene Default-/Optional-Scopes) und Settings → Login settings → Consent required",
        ),
        (Consent, Okta) => (
            "Applications → <app> → Okta API Scopes; Security → API → <authorization server> → Scopes and Access Policies → Rules",
            "Applications → <app> → Okta API Scopes; Security → API → <authorization server> → Scopes und Access Policies → Rules",
        ),
        (Consent, Auth0) => (
            "Applications → <app> → APIs (authorized APIs and permissions); APIs → <api> → Permissions",
            "Applications → <app> → APIs (autorisierte APIs und Berechtigungen); APIs → <api> → Permissions",
        ),
        (Consent, Cognito) => (
            "User pool → App clients → <client> → Login pages → OpenID Connect scopes / custom scopes of resource servers",
            "User pool → App clients → <client> → Login pages → OpenID Connect scopes / eigene Scopes der Resource Server",
        ),
        (Consent, Google) => (
            "Google Cloud console → APIs & Services → OAuth consent screen → Scopes (and enable the API)",
            "Google Cloud console → APIs & Services → OAuth consent screen → Scopes (und die API aktivieren)",
        ),
        (Consent, Adfs) => (
            "AD FS Management → Application Groups → <web API> → Client Permissions (permitted scopes)",
            "AD FS Management → Application Groups → <web API> → Client Permissions (erlaubte Scopes)",
        ),
        (Consent, Duende) => ("Client.AllowedScopes and the ApiScopes / IdentityResources definitions", "Client.AllowedScopes und die Definitionen der ApiScopes / IdentityResources"),
        (Consent, Ping) => (
            "Applications → OAuth → Clients → <client> → Restrict Common Scopes / Exclusive scopes",
            "Applications → OAuth → Clients → <client> → Restrict Common Scopes / Exclusive scopes",
        ),
        (Flows, Entra | EntraExternal | EntraB2c) => (
            "App registrations → <app> → Authentication → Implicit grant and hybrid flows (ID tokens / Access tokens) and Advanced settings → Allow public client flows (device code, ROPC)",
            "App registrations → <app> → Authentication → Implicit grant and hybrid flows (ID tokens / Access tokens) und Advanced settings → Allow public client flows (Gerätecode, ROPC)",
        ),
        (Flows, Keycloak) => (
            "Clients → <client> → Settings → Capability config (Standard flow, Direct access grants, Implicit flow, Service accounts roles, OAuth 2.0 Device Authorization Grant; Client authentication On/Off)",
            "Clients → <client> → Settings → Capability config (Standard flow, Direct access grants, Implicit flow, Service accounts roles, OAuth 2.0 Device Authorization Grant; Client authentication On/Off)",
        ),
        (Flows, Okta) => ("Applications → <app> → General → General Settings → Grant type", "Applications → <app> → General → General Settings → Grant type"),
        (Flows, Auth0) => ("Applications → <app> → Settings → Advanced Settings → Grant Types", "Applications → <app> → Settings → Advanced Settings → Grant Types"),
        (Flows, Cognito) => ("User pool → App clients → <client> → Login pages → OAuth 2.0 grant types", "User pool → App clients → <client> → Login pages → OAuth 2.0 grant types"),
        (Flows, Google) => (
            "OAuth client type (Web application, Desktop, TV/limited input) in Google Cloud console → Credentials",
            "Typ des OAuth-Clients (Web application, Desktop, TV/limited input) in Google Cloud console → Credentials",
        ),
        (Flows, Adfs) => (
            "AD FS Management → Application Groups (native vs. server application; Grant-AdfsApplicationPermission)",
            "AD FS Management → Application Groups (Native vs. Server Application; Grant-AdfsApplicationPermission)",
        ),
        (Flows, Duende) => ("Client.AllowedGrantTypes (GrantTypes.Code, ClientCredentials, DeviceFlow …)", "Client.AllowedGrantTypes (GrantTypes.Code, ClientCredentials, DeviceFlow …)"),
        (Flows, Ping) => ("Applications → OAuth → Clients → <client> → Allowed Grant Types", "Applications → OAuth → Clients → <client> → Allowed Grant Types"),
        (Pkce, Entra | EntraExternal | EntraB2c) => (
            "Register browser apps under the Single-page application platform (PKCE required; MSAL.js 2+ uses auth code + PKCE)",
            "Browser-Apps unter der Plattform Single-page application registrieren (PKCE erforderlich; MSAL.js 2+ verwendet Authorization Code + PKCE)",
        ),
        (Pkce, Keycloak) => (
            "Clients → <client> → Advanced → Advanced settings → Proof Key for Code Exchange Code Challenge Method: S256",
            "Clients → <client> → Advanced → Advanced settings → Proof Key for Code Exchange Code Challenge Method: S256",
        ),
        (Pkce, Okta) => (
            "Applications → <app> → General → Client Credentials → Require PKCE as additional verification",
            "Applications → <app> → General → Client Credentials → Require PKCE as additional verification",
        ),
        (Pkce, Auth0) => (
            "Use an SDK that sends code_challenge (auth0-spa-js, Auth0.Android/Swift); public clients: Application Type Single Page / Native",
            "Ein SDK verwenden, das code_challenge sendet (auth0-spa-js, Auth0.Android/Swift); öffentliche Clients: Application Type Single Page / Native",
        ),
        (Pkce, Cognito) => (
            "Send code_challenge with code_challenge_method=S256 to /oauth2/authorize (supported by the hosted login pages)",
            "code_challenge mit code_challenge_method=S256 an /oauth2/authorize senden (von den gehosteten Anmeldeseiten unterstützt)",
        ),
        (Pkce, Google) => (
            "Send code_challenge with code_challenge_method=S256 (required for installed apps)",
            "code_challenge mit code_challenge_method=S256 senden (für installierte Apps erforderlich)",
        ),
        (Pkce, Duende) => ("Client.RequirePkce = true (default) and AllowPlainTextPkce = false", "Client.RequirePkce = true (Standard) und AllowPlainTextPkce = false"),
        (Pkce, Ping) => (
            "Applications → OAuth → Clients → <client> → Require Proof Key for Code Exchange (PKCE)",
            "Applications → OAuth → Clients → <client> → Require Proof Key for Code Exchange (PKCE)",
        ),
        (Lifetime, Entra | EntraExternal) => (
            "Access tokens live 60–90 min (CAE: up to 28 h); refresh/session lifetime via Protection → Conditional Access → Session → Sign-in frequency; SPA refresh tokens 24 h",
            "Access Tokens gelten 60–90 min (CAE: bis 28 h); Refresh-/Sitzungsdauer über Protection → Conditional Access → Session → Sign-in frequency; Refresh Tokens von SPAs 24 h",
        ),
        (Lifetime, EntraB2c) => (
            "Azure AD B2C → User flows → <flow> → Properties → Token lifetime / Session behavior",
            "Azure AD B2C → User flows → <flow> → Properties → Token lifetime / Session behavior",
        ),
        (Lifetime, Keycloak) => (
            "Realm settings → Tokens (Access Token Lifespan) and Realm settings → Sessions (SSO Session Idle / Max, Client session idle, Offline Session Idle); per client: Clients → <client> → Advanced → Advanced settings",
            "Realm settings → Tokens (Access Token Lifespan) und Realm settings → Sessions (SSO Session Idle / Max, Client session idle, Offline Session Idle); je Client: Clients → <client> → Advanced → Advanced settings",
        ),
        (Lifetime, Okta) => (
            "Security → API → <authorization server> → Access Policies → <rule> → token lifetimes",
            "Security → API → <authorization server> → Access Policies → <rule> → Token-Laufzeiten",
        ),
        (Lifetime, Auth0) => (
            "APIs → <api> → Settings → Token Expiration; Applications → <app> → Settings → Refresh Token Rotation / Expiration",
            "APIs → <api> → Settings → Token Expiration; Applications → <app> → Settings → Refresh Token Rotation / Expiration",
        ),
        (Lifetime, Cognito) => (
            "User pool → App clients → <client> → Token expiration (access, ID, refresh)",
            "User pool → App clients → <client> → Token expiration (Access, ID, Refresh)",
        ),
        (Lifetime, Google) => (
            "Access tokens live 1 h; refresh tokens of apps in 'Testing' status expire after 7 days (OAuth consent screen → Publishing status)",
            "Access Tokens gelten 1 h; Refresh Tokens von Apps im Status „Testing“ laufen nach 7 Tagen ab (OAuth consent screen → Publishing status)",
        ),
        (Lifetime, Adfs) => (
            "Set-AdfsRelyingPartyTrust -TokenLifetime; Set-AdfsApplicationPermission / SSO lifetime (Set-AdfsProperties -SsoLifetime)",
            "Set-AdfsRelyingPartyTrust -TokenLifetime; Set-AdfsApplicationPermission / SSO-Laufzeit (Set-AdfsProperties -SsoLifetime)",
        ),
        (Lifetime, Duende) => (
            "Client.AccessTokenLifetime, IdentityTokenLifetime, AbsoluteRefreshTokenLifetime, SlidingRefreshTokenLifetime, RefreshTokenUsage",
            "Client.AccessTokenLifetime, IdentityTokenLifetime, AbsoluteRefreshTokenLifetime, SlidingRefreshTokenLifetime, RefreshTokenUsage",
        ),
        (Lifetime, Ping) => (
            "Access token management → <ATM> → Token lifetime; OAuth settings → Refresh token policy",
            "Access token management → <ATM> → Token lifetime; OAuth settings → Refresh token policy",
        ),
        (Audience, Entra | EntraExternal) => (
            "API app: App registrations → <api> → Expose an API → Application ID URI (= aud) and Manifest → accessTokenAcceptedVersion / api.requestedAccessTokenVersion (2 for v2 tokens); client: request the API's scope (api://<id>/<scope> or api://<id>/.default), not a Microsoft Graph scope",
            "API-App: App registrations → <api> → Expose an API → Application ID URI (= aud) und Manifest → accessTokenAcceptedVersion / api.requestedAccessTokenVersion (2 für v2-Tokens); Client: den Scope der API anfordern (api://<id>/<scope> oder api://<id>/.default), keinen Microsoft-Graph-Scope",
        ),
        (Audience, EntraB2c) => (
            "Azure AD B2C → App registrations → <api> → Expose an API (scope URI); the client must request that scope",
            "Azure AD B2C → App registrations → <api> → Expose an API (Scope-URI); der Client muss diesen Scope anfordern",
        ),
        (Audience, Keycloak) => (
            "Client scopes → <scope> or Clients → <client> → Client scopes → <client>-dedicated → Add mapper → Audience (Included Client Audience)",
            "Client scopes → <scope> oder Clients → <client> → Client scopes → <client>-dedicated → Add mapper → Audience (Included Client Audience)",
        ),
        (Audience, Okta) => (
            "Security → API → <authorization server> → Settings → Audience (and issuer: the API must validate against this authorization server)",
            "Security → API → <authorization server> → Settings → Audience (und Issuer: Die API muss gegen diesen Authorization Server validieren)",
        ),
        (Audience, Auth0) => (
            "Send audience=<API Identifier> in the authorize/token request (APIs → <api> → Settings → Identifier)",
            "audience=<API Identifier> im Authorize-/Token-Request senden (APIs → <api> → Settings → Identifier)",
        ),
        (Audience, Cognito) => (
            "Cognito access tokens carry client_id instead of aud: validate client_id and token_use=access",
            "Access Tokens von Cognito enthalten client_id statt aud: client_id und token_use=access validieren",
        ),
        (Audience, Google) => (
            "Google ID tokens carry the client id as aud; access tokens are opaque (validate via tokeninfo)",
            "ID-Tokens von Google enthalten die Client-ID als aud; Access Tokens sind opak (über tokeninfo validieren)",
        ),
        (Audience, Adfs) => (
            "AD FS Management → Application Groups → <web API> → Identifiers (relying party identifier = aud)",
            "AD FS Management → Application Groups → <web API> → Identifiers (Relying-Party-Bezeichner = aud)",
        ),
        (Audience, Duende) => (
            "ApiResource (Name becomes aud) with its Scopes; the client must request one of them",
            "ApiResource (Name wird zu aud) mit ihren Scopes; der Client muss einen davon anfordern",
        ),
        (Audience, Ping) => (
            "Access token management → <ATM> → Audience claim; resource URIs of the client",
            "Access token management → <ATM> → Audience claim; Ressourcen-URIs des Clients",
        ),
        (Cors, Entra | EntraExternal | EntraB2c) => (
            "Register the browser app's redirect URI under the Single-page application platform (enables CORS on the token endpoint)",
            "Die Redirect-URI der Browser-App unter der Plattform Single-page application registrieren (aktiviert CORS am Token-Endpunkt)",
        ),
        (Cors, Keycloak) => (
            "Clients → <client> → Settings → Web origins (+ for all valid redirect URIs)",
            "Clients → <client> → Settings → Web origins (+ für alle gültigen Redirect-URIs)",
        ),
        (Cors, Okta) => ("Security → API → Trusted Origins (CORS)", "Security → API → Trusted Origins (CORS)"),
        (Cors, Auth0) => (
            "Applications → <app> → Settings → Allowed Web Origins and Allowed Origins (CORS)",
            "Applications → <app> → Settings → Allowed Web Origins und Allowed Origins (CORS)",
        ),
        (Cors, Duende) => ("Client.AllowedCorsOrigins", "Client.AllowedCorsOrigins"),
        (Logs, Entra | EntraExternal | EntraB2c) => (
            "Entra admin center → Monitoring & health → Sign-in logs (filter Request ID = trace id or Correlation ID; tabs Basic info, Conditional Access); error lookup: https://login.microsoftonline.com/error?code=<n>",
            "Entra admin center → Monitoring & health → Sign-in logs (nach Request ID = Trace-ID oder Correlation ID filtern; Registerkarten Basic info, Conditional Access); Fehlercode nachschlagen: https://login.microsoftonline.com/error?code=<n>",
        ),
        (Logs, Keycloak) => (
            "Realm settings → Events → User events settings (Save events on) → Events list; plus the server log",
            "Realm settings → Events → User events settings (Save events on) → Events list; dazu das Server-Log",
        ),
        (Logs, Okta) => ("Reports → System Log (search by the request id / client id)", "Reports → System Log (nach Request-ID / Client-ID suchen)"),
        (Logs, Auth0) => ("Monitoring → Logs", "Monitoring → Logs"),
        (Logs, Cognito) => ("AWS CloudTrail and the user pool log streaming (CloudWatch)", "AWS CloudTrail und das Log-Streaming des User Pools (CloudWatch)"),
        (Logs, Google) => ("Google Cloud console → Logging → Logs Explorer", "Google Cloud console → Logging → Logs Explorer"),
        (Logs, Adfs) => (
            "Event Viewer → Applications and Services Logs → AD FS → Admin on the AD FS servers (search by the activity id)",
            "Event Viewer → Applications and Services Logs → AD FS → Admin auf den AD-FS-Servern (nach der Activity-ID suchen)",
        ),
        (Logs, Duende) => (
            "IdentityServer server log and events (Options.Events.RaiseErrorEvents / RaiseFailureEvents)",
            "Server-Log und Events von IdentityServer (Options.Events.RaiseErrorEvents / RaiseFailureEvents)",
        ),
        (Logs, Ping) => ("PingFederate server.log and audit.log", "PingFederate server.log und audit.log"),
        (Groups, Entra | EntraExternal) => (
            "App registrations → <app> → Token configuration → Add groups claim → 'Groups assigned to the application' (or use app roles); over 200 groups Entra sends a groups overage claim instead — resolve via Microsoft Graph",
            "App registrations → <app> → Token configuration → Add groups claim → „Groups assigned to the application“ (oder App-Rollen verwenden); bei über 200 Gruppen sendet Entra stattdessen einen Groups-Overage-Claim – über Microsoft Graph auflösen",
        ),
        (Groups, Keycloak) => (
            "Clients → <client> → Client scopes → <client>-dedicated → Scope → Full scope allowed Off; remove group/role mappers that add every membership",
            "Clients → <client> → Client scopes → <client>-dedicated → Scope → Full scope allowed Off; Gruppen-/Rollen-Mapper entfernen, die jede Mitgliedschaft hinzufügen",
        ),
        (Groups, Okta) => (
            "Security → API → <authorization server> → Claims → groups claim with a filter (e.g. Starts with)",
            "Security → API → <authorization server> → Claims → groups-Claim mit einem Filter (z. B. Starts with)",
        ),
        (Groups, Auth0) => ("Actions → Login flow: add only the claims the API needs", "Actions → Login flow: nur die Claims hinzufügen, die die API braucht"),
        (Groups, Adfs) => (
            "Relying party trust → Edit Claim Issuance Policy: emit only the needed group claims",
            "Relying party trust → Edit Claim Issuance Policy: nur die benötigten Gruppen-Claims ausgeben",
        ),
        (Groups, Duende) => (
            "Only the needed claims in IdentityResources/ApiResources UserClaims (or a profile service that filters)",
            "Nur die benötigten Claims in IdentityResources/ApiResources UserClaims (oder ein filternder Profile Service)",
        ),
        (SilentRenew, Entra | EntraExternal | EntraB2c) => (
            "MSAL.js 2+ (msal-browser) uses refresh tokens in single-page apps instead of hidden iframes; acquireTokenSilent falls back to the iframe only when the refresh token expired",
            "MSAL.js 2+ (msal-browser) verwendet in Single-Page-Apps Refresh Tokens statt versteckter Iframes; acquireTokenSilent weicht nur auf das Iframe aus, wenn das Refresh Token abgelaufen ist",
        ),
        (SilentRenew, Keycloak) => (
            "keycloak-js: use refresh tokens (updateToken) and checkLoginIframe: false; silent-check-sso iframes break without third-party cookies",
            "keycloak-js: Refresh Tokens verwenden (updateToken) und checkLoginIframe: false; silent-check-sso-Iframes funktionieren ohne Drittanbieter-Cookies nicht",
        ),
        (SilentRenew, Okta) => (
            "Okta Auth JS: tokenManager autoRenew with refresh tokens (Applications → <app> → Grant type → Refresh Token, rotation)",
            "Okta Auth JS: tokenManager autoRenew mit Refresh Tokens (Applications → <app> → Grant type → Refresh Token, Rotation)",
        ),
        (SilentRenew, Auth0) => (
            "auth0-spa-js: useRefreshTokens: true with refresh token rotation, or a custom domain on the app's site so the session cookie is first-party",
            "auth0-spa-js: useRefreshTokens: true mit Refresh-Token-Rotation, oder eine Custom Domain auf der Site der App, damit das Sitzungs-Cookie First-Party ist",
        ),
        (SilentRenew, Generic | Duende | Cognito | Ping | Adfs | Google) => (
            "oidc-client-ts / angular-oauth2-oidc: useRefreshToken (refresh tokens with rotation) instead of silent renew in an iframe",
            "oidc-client-ts / angular-oauth2-oidc: useRefreshToken (Refresh Tokens mit Rotation) statt Silent Renew im Iframe",
        ),
        (AccessPolicy, Entra | EntraExternal | EntraB2c) => (
            "Protection → Conditional Access → Policies (the sign-in log's Conditional Access tab names the policy that applied)",
            "Protection → Conditional Access → Policies (die Registerkarte Conditional Access im Sign-in log nennt die angewendete Richtlinie)",
        ),
        (AccessPolicy, Keycloak) => ("Authentication → Flows (conditional OTP, required actions)", "Authentication → Flows (bedingtes OTP, Required Actions)"),
        (AccessPolicy, Okta) => ("Security → Authentication Policies / Global Session Policy", "Security → Authentication Policies / Global Session Policy"),
        (AccessPolicy, Auth0) => ("Security → Multi-factor Auth and Actions → Login flow", "Security → Multi-factor Auth und Actions → Login flow"),
        (AccessPolicy, Adfs) => ("AD FS Management → Access Control Policies", "AD FS Management → Access Control Policies"),
        (Assignment, Entra | EntraExternal) => (
            "Enterprise applications → <app> → Users and groups (assign the user or a group), or Properties → Assignment required? = No",
            "Enterprise applications → <app> → Users and groups (den Benutzer oder eine Gruppe zuweisen) oder Properties → Assignment required? = No",
        ),
        (Assignment, Okta) => ("Applications → <app> → Assignments", "Applications → <app> → Assignments"),
        (Assignment, Auth0) => (
            "Applications → <app> → Connections (enabled connections) and Organizations",
            "Applications → <app> → Connections (aktivierte Connections) und Organizations",
        ),
        (Assignment, Keycloak) => (
            "Users → <user> → Role mapping (client roles required by the application)",
            "Users → <user> → Role mapping (von der Anwendung verlangte Client-Rollen)",
        ),
        (Tenant, Entra | EntraExternal | EntraB2c) => (
            "Use the tenant-specific authority https://login.microsoftonline.com/<tenant id>/ for single-tenant apps; App registrations → <app> → Authentication → Supported account types for multi-tenant apps",
            "Für Single-Tenant-Apps die mandantenspezifische Authority https://login.microsoftonline.com/<tenant id>/ verwenden; für mandantenübergreifende Apps App registrations → <app> → Authentication → Supported account types",
        ),
        (Tenant, Keycloak) => (
            "The realm in the authority URL (…/realms/<realm>) must be the one the client is defined in",
            "Der Realm in der Authority-URL (…/realms/<realm>) muss der sein, in dem der Client definiert ist",
        ),
        (Tenant, Okta) => (
            "The authorization server in the authority (…/oauth2/default or …/oauth2/<id>) must be the one the app uses",
            "Der Authorization Server in der Authority (…/oauth2/default oder …/oauth2/<id>) muss der sein, den die App verwendet",
        ),
        _ => return None,
    })
}

// ------------------------------------------------------------------ error knowledge

/// How an error should be weighed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Part of a normal flow (device flow polling, "stay signed in?").
    Normal,
    /// The user has to act (MFA, consent, interactive sign-in).
    Interaction,
    /// The user's account or credentials.
    User,
    /// A policy (Conditional Access, device compliance) blocks the request.
    Policy,
    /// Configuration of the app registration or the request.
    Config,
    /// Client credentials (secret, certificate, assertion).
    Credential,
    /// The grant (code, refresh token) is invalid, expired or reused.
    Grant,
    /// A token presented to an API or the IdP is invalid.
    Token,
    /// The IdP is temporarily unavailable.
    Transient,
}

/// Explanation of one error code or text.
#[derive(Debug)]
pub struct Entry {
    pub name: &'static str,
    pub class: Class,
    pub topic: Option<Topic>,
    pub cause: (&'static str, &'static str),
    pub fix: (&'static str, &'static str),
}

impl Entry {
    /// The text of a pair in the report language.
    pub fn pick(pair: (&'static str, &'static str), ctx: &crate::model::Ctx) -> &'static str {
        if ctx.de() { pair.1 } else { pair.0 }
    }
}

const fn e(name: &'static str, class: Class, topic: Option<Topic>, cause_en: &'static str, cause_de: &'static str, fix_en: &'static str, fix_de: &'static str) -> Entry {
    Entry { name, class, topic, cause: (cause_en, cause_de), fix: (fix_en, fix_de) }
}

use Class::*;
use Topic::*;

const INTERACTIVE_EN: &str = "Acquire the token interactively (handle the claims challenge); non-interactive flows such as ROPC or client credentials cannot do this.";
const INTERACTIVE_DE: &str = "Das Token interaktiv anfordern (Claims-Challenge behandeln); nicht interaktive Flows wie ROPC oder Client Credentials können das nicht.";
const SIGN_IN_AGAIN_EN: &str = "Discard the cached tokens and sign in again interactively.";
const SIGN_IN_AGAIN_DE: &str = "Die zwischengespeicherten Tokens verwerfen und erneut interaktiv anmelden.";
const CA_EN: &str = "Find the policy in the sign-in log (Conditional Access tab) and check its conditions (location, app, platform, device).";
const CA_DE: &str = "Die Richtlinie im Anmeldeprotokoll (Registerkarte „Bedingter Zugriff“) suchen und ihre Bedingungen prüfen (Standort, App, Plattform, Gerät).";

/// Entra ID `AADSTS` codes (the most common ones).
pub const AADSTS: &[(u32, Entry)] = &[
    (16000, e("SelectUserAccount", Interaction, None, "Several accounts or no matching session: the user has to choose an account.", "Mehrere Konten oder keine passende Sitzung: Der Benutzer muss ein Konto auswählen.", "Retry interactively (prompt=select_account) or pass login_hint / domain_hint.", "Interaktiv wiederholen (prompt=select_account) oder login_hint/domain_hint mitgeben.")),
    (16001, e("UserAccountSelectionInvalid", Interaction, None, "The account chosen cannot be used for this session.", "Das gewählte Konto kann für diese Sitzung nicht verwendet werden.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (50001, e("InvalidResource", Config, Some(Consent), "The requested resource (API) does not exist in the tenant or is disabled.", "Die angeforderte Ressource (API) existiert im Mandanten nicht oder ist deaktiviert.", "Check the resource/scope URI (Application ID URI) and that the API is provisioned in this tenant.", "Ressourcen-/Scope-URI (Application ID URI) prüfen und ob die API in diesem Mandanten bereitgestellt ist.")),
    (50011, e("InvalidReplyTo", Config, Some(RedirectUri), "The redirect_uri of the request does not exactly match a redirect URI registered for the app.", "Die redirect_uri des Requests stimmt nicht exakt mit einer für die App registrierten Redirect-URI überein.", "Register the exact redirect URI (scheme, host, port, path, trailing slash) on the right platform, or fix the URI the app sends.", "Die exakte Redirect-URI (Schema, Host, Port, Pfad, abschließender Schrägstrich) auf der richtigen Plattform registrieren oder die gesendete URI korrigieren.")),
    (50012, e("AuthenticationFailed", Credential, Some(ClientCredentials), "Client authentication failed: the client assertion is invalid (signature, certificate, audience).", "Die Client-Authentifizierung ist fehlgeschlagen: Die Client-Assertion ist ungültig (Signatur, Zertifikat, Audience).", "Check the certificate registered for the app and the assertion's aud (the token endpoint URL).", "Das für die App registrierte Zertifikat und das aud der Assertion (URL des Token-Endpunkts) prüfen.")),
    (50013, e("InvalidAssertion", Token, Some(Audience), "The assertion (e.g. the user token in on-behalf-of) is invalid: wrong audience, expired or not for this app.", "Die Assertion (z. B. das Benutzertoken bei On-Behalf-Of) ist ungültig: falsche Audience, abgelaufen oder nicht für diese App.", "Pass a token issued for the middle-tier API itself (aud = its App ID URI) before it expires.", "Ein für die Middle-Tier-API selbst ausgestelltes Token (aud = deren App ID URI) vor Ablauf übergeben.")),
    (50020, e("UserUnauthorized", User, Some(Tenant), "The account is from another tenant or identity provider and is not a guest in this tenant.", "Das Konto stammt aus einem anderen Mandanten oder Identity Provider und ist kein Gast in diesem Mandanten.", "Invite the user as a guest, use the right tenant in the authority, or make the app multi-tenant.", "Den Benutzer als Gast einladen, den richtigen Mandanten in der Authority verwenden oder die App mandantenübergreifend machen.")),
    (50027, e("InvalidJwtToken", Token, None, "An invalid JWT was presented (expired, wrong issuer, missing nonce or signature).", "Ein ungültiges JWT wurde vorgelegt (abgelaufen, falscher Aussteller, fehlende Nonce oder Signatur).", "Check the token the client sends (assertion, id_token_hint) and its lifetime.", "Das vom Client gesendete Token (Assertion, id_token_hint) und seine Laufzeit prüfen.")),
    (50034, e("UserAccountNotFound", User, Some(Tenant), "The user account does not exist in this directory.", "Das Benutzerkonto existiert in diesem Verzeichnis nicht.", "Check the user name and the tenant (tenant-specific vs. common endpoint).", "Benutzernamen und Mandanten prüfen (mandantenspezifischer vs. common-Endpunkt).")),
    (50053, e("IdsLocked", User, Some(AccessPolicy), "The account is locked after too many failed sign-ins, or sign-in from a suspicious IP was blocked.", "Das Konto ist nach zu vielen Fehlversuchen gesperrt, oder die Anmeldung von einer verdächtigen IP wurde blockiert.", "Wait for the lockout to end and find the source of the failed attempts (often a client with an old password).", "Das Ende der Sperre abwarten und die Quelle der Fehlversuche finden (oft ein Client mit altem Passwort).")),
    (50055, e("InvalidPasswordExpiredPassword", User, None, "The user's password has expired.", "Das Passwort des Benutzers ist abgelaufen.", "Change the password; for services use a workload identity instead of a user account.", "Das Passwort ändern; für Dienste eine Workload-Identität statt eines Benutzerkontos verwenden.")),
    (50057, e("UserDisabled", User, None, "The user account is disabled.", "Das Benutzerkonto ist deaktiviert.", "Enable the account or use another one.", "Das Konto aktivieren oder ein anderes verwenden.")),
    (50058, e("UserInformationNotProvided", Interaction, Some(SilentRenew), "Silent sign-in failed: there is no session at the IdP (no or blocked cookies, e.g. third-party cookies in a hidden iframe).", "Die stille Anmeldung schlug fehl: Beim IdP besteht keine Sitzung (keine oder blockierte Cookies, z. B. Drittanbieter-Cookies im versteckten iframe).", "Fall back to interactive sign-in; prefer refresh tokens over hidden iframes.", "Auf die interaktive Anmeldung ausweichen; Refresh-Tokens statt versteckter iframes bevorzugen.")),
    (50059, e("MissingTenantRealmAndNoUserInformationProvided", Config, Some(Tenant), "The tenant could not be determined (common endpoint without user information).", "Der Mandant konnte nicht ermittelt werden (common-Endpunkt ohne Benutzerinformation).", "Use the tenant-specific authority (login.microsoftonline.com/<tenant id>).", "Die mandantenspezifische Authority verwenden (login.microsoftonline.com/<Mandanten-ID>).")),
    (50072, e("UserStrongAuthEnrollmentRequiredInterrupt", Interaction, Some(AccessPolicy), "The user must register for multi-factor authentication.", "Der Benutzer muss sich für die Multi-Faktor-Authentifizierung registrieren.", "Let the user complete the MFA registration interactively.", "Den Benutzer die MFA-Registrierung interaktiv abschließen lassen.")),
    (50074, e("UserStrongAuthClientAuthNRequiredInterrupt", Interaction, Some(AccessPolicy), "Strong authentication (MFA) is required and must be done interactively.", "Starke Authentifizierung (MFA) ist erforderlich und muss interaktiv erfolgen.", INTERACTIVE_EN, INTERACTIVE_DE)),
    (50076, e("UserStrongAuthClientAuthNRequired", Interaction, Some(AccessPolicy), "MFA is required (Conditional Access, new location or changed policy) and the request did not satisfy it.", "MFA ist erforderlich (Bedingter Zugriff, neuer Standort oder geänderte Richtlinie), und der Request hat sie nicht erfüllt.", INTERACTIVE_EN, INTERACTIVE_DE)),
    (50079, e("UserStrongAuthEnrollmentRequired", Interaction, Some(AccessPolicy), "The user has to register security information for MFA first.", "Der Benutzer muss zuerst Sicherheitsinformationen für MFA registrieren.", "Have the user register (https://aka.ms/mysecurityinfo), then sign in interactively.", "Den Benutzer registrieren lassen (https://aka.ms/mysecurityinfo) und dann interaktiv anmelden.")),
    (50089, e("FlowTokenExpired", Interaction, None, "The sign-in took too long; the flow token expired.", "Die Anmeldung dauerte zu lange; das Flow-Token ist abgelaufen.", "Start the sign-in again.", "Die Anmeldung neu starten.")),
    (50097, e("DeviceAuthenticationRequired", Policy, Some(AccessPolicy), "Device authentication is required (Conditional Access: registered, joined or compliant device).", "Geräteauthentifizierung ist erforderlich (Bedingter Zugriff: registriertes, eingebundenes oder konformes Gerät).", "Sign in from a registered device, through a broker (WAM, Company Portal, Authenticator).", "Von einem registrierten Gerät über einen Broker anmelden (WAM, Unternehmensportal, Authenticator).")),
    (50105, e("EntitlementGrantsNotFound", Config, Some(Assignment), "The user is not assigned to the application (assignment required).", "Der Benutzer ist der Anwendung nicht zugewiesen (Zuweisung erforderlich).", "Assign the user or a group to the app, or turn off 'Assignment required'.", "Den Benutzer oder eine Gruppe der App zuweisen oder „Zuweisung erforderlich“ abschalten.")),
    (50126, e("InvalidUserNameOrPassword", User, None, "Wrong user name or password.", "Falscher Benutzername oder falsches Passwort.", "Check the credentials; repeated failures lock the account (50053).", "Die Anmeldedaten prüfen; wiederholte Fehlversuche sperren das Konto (50053).")),
    (50128, e("InvalidDomainName", Config, Some(Tenant), "No tenant was found for the domain of the user name or the authority.", "Für die Domain des Benutzernamens oder der Authority wurde kein Mandant gefunden.", "Check the tenant name in the authority and the user's domain.", "Den Mandantennamen in der Authority und die Domain des Benutzers prüfen.")),
    (50132, e("SsoArtifactInvalidOrExpired", Interaction, Some(Lifetime), "The session is no longer valid (password changed or session expired).", "Die Sitzung ist nicht mehr gültig (Passwort geändert oder Sitzung abgelaufen).", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (50133, e("SsoArtifactRevoked", Interaction, Some(Lifetime), "The session was revoked (password change or administrator).", "Die Sitzung wurde widerrufen (Passwortänderung oder Administrator).", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (50140, e("KmsiInterrupt", Normal, None, "The 'Stay signed in?' prompt interrupted the sign-in — part of the normal flow.", "Die Abfrage „Angemeldet bleiben?“ hat die Anmeldung unterbrochen – Teil des normalen Ablaufs.", "Nothing to do unless it repeats for the same user.", "Nichts zu tun, sofern es sich für denselben Benutzer nicht wiederholt.")),
    (50146, e("MissingCustomSigningKey", Config, Some(Audience), "The app needs an app-specific signing key (claims mapping) but has none, or it expired.", "Die App benötigt einen app-spezifischen Signaturschlüssel (Claims-Mapping), hat aber keinen, oder er ist abgelaufen.", "Configure a custom signing key, set acceptMappedClaims in the manifest, or remove the claims mapping policy.", "Einen eigenen Signaturschlüssel konfigurieren, acceptMappedClaims im Manifest setzen oder die Claims-Mapping-Richtlinie entfernen.")),
    (50148, e("CodeVerifierMismatch", Grant, Some(Pkce), "The code_verifier does not match the code_challenge of the authorization request (PKCE).", "Der code_verifier passt nicht zur code_challenge des Autorisierungs-Requests (PKCE).", "Send the code_verifier generated for this very authorization request (not one of another tab or attempt).", "Den für genau diesen Autorisierungs-Request erzeugten code_verifier senden (nicht den eines anderen Tabs oder Versuchs).")),
    (501481, e("CodeVerifierMismatch", Grant, Some(Pkce), "The code_verifier does not match the code_challenge of the authorization request (PKCE).", "Der code_verifier passt nicht zur code_challenge des Autorisierungs-Requests (PKCE).", "Keep code_verifier and state together per attempt (session storage per tab) and redeem with the matching one.", "code_verifier und state pro Versuch zusammenhalten (Session Storage pro Tab) und mit dem passenden einlösen.")),
    (50158, e("ExternalSecurityChallenge", Interaction, Some(AccessPolicy), "An external security challenge (external MFA, policy) was not satisfied.", "Eine externe Sicherheitsabfrage (externe MFA, Richtlinie) wurde nicht erfüllt.", INTERACTIVE_EN, INTERACTIVE_DE)),
    (50173, e("FreshTokenNeeded", Grant, Some(Lifetime), "The grant was revoked (password change, administrator); a fresh sign-in is needed.", "Die Berechtigung wurde widerrufen (Passwortänderung, Administrator); eine neue Anmeldung ist nötig.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (50194, e("InvalidMultiTenantApplication", Config, Some(Tenant), "The app is single-tenant but the request used /common or /organizations.", "Die App ist einmandantenfähig, der Request verwendete aber /common oder /organizations.", "Use the tenant-specific authority or change the supported account types.", "Die mandantenspezifische Authority verwenden oder die unterstützten Kontotypen ändern.")),
    (50196, e("LoopDetected", Config, None, "Entra ID detected a client loop: the same request many times in a short time.", "Entra ID hat eine Client-Schleife erkannt: derselbe Request viele Male in kurzer Zeit.", "Fix the loop in the app (lost cookie, token not cached) — see OIDC-LOOP and TOKEN-REFRESH.", "Die Schleife in der App beheben (verlorenes Cookie, Token nicht gecacht) – siehe OIDC-LOOP und TOKEN-REFRESH.")),
    (50199, e("CmsiInterrupt", Normal, None, "A security confirmation for a native app redirect interrupted the sign-in.", "Eine Sicherheitsbestätigung für die Weiterleitung einer nativen App hat die Anmeldung unterbrochen.", "Normal for native apps without a broker; use a redirect URI the broker handles to avoid it.", "Normal bei nativen Apps ohne Broker; eine vom Broker verarbeitete Redirect-URI vermeidet es.")),
    (51004, e("UserAccountNotInDirectory", User, Some(Tenant), "The user account does not exist in the directory.", "Das Benutzerkonto existiert im Verzeichnis nicht.", "Check the user name and the tenant.", "Benutzernamen und Mandanten prüfen.")),
    (53000, e("DeviceNotCompliant", Policy, Some(AccessPolicy), "Conditional Access requires a compliant device.", "Bedingter Zugriff verlangt ein konformes Gerät.", CA_EN, CA_DE)),
    (53001, e("DeviceNotDomainJoined", Policy, Some(AccessPolicy), "Conditional Access requires a (hybrid) domain-joined device.", "Bedingter Zugriff verlangt ein (hybrid) in die Domäne eingebundenes Gerät.", CA_EN, CA_DE)),
    (53003, e("BlockedByConditionalAccess", Policy, Some(AccessPolicy), "A Conditional Access policy blocked the sign-in.", "Eine Richtlinie für bedingten Zugriff hat die Anmeldung blockiert.", CA_EN, CA_DE)),
    (530032, e("BlockedByConditionalAccessOnSecurityPolicy", Policy, Some(AccessPolicy), "A tenant security policy blocked the request.", "Eine Sicherheitsrichtlinie des Mandanten hat den Request blockiert.", CA_EN, CA_DE)),
    (54005, e("OAuth2 code already redeemed", Grant, None, "The authorization code was already redeemed (codes are single-use).", "Der Autorisierungscode wurde bereits eingelöst (Codes gelten nur einmal).", "Redeem each code once; look for double callbacks (reload, two handlers, retries).", "Jeden Code nur einmal einlösen; nach doppelten Callbacks suchen (Neuladen, zwei Handler, Wiederholungen).")),
    (65001, e("DelegationDoesNotExist", Config, Some(Consent), "The user or an administrator has not consented to the requested permissions.", "Der Benutzer oder ein Administrator hat den angeforderten Berechtigungen nicht zugestimmt.", "Grant consent for the permissions (admin consent for the tenant).", "Die Zustimmung für die Berechtigungen erteilen (Administratorzustimmung für den Mandanten).")),
    (65004, e("UserDeclinedConsent", Interaction, Some(Consent), "The user declined consent.", "Der Benutzer hat die Zustimmung abgelehnt.", "Ask for fewer permissions or have an administrator consent for the tenant.", "Weniger Berechtigungen anfordern oder einen Administrator für den Mandanten zustimmen lassen.")),
    (650052, e("ServiceNotSubscribed", Config, Some(Consent), "The app needs access to a service the organisation has not subscribed to or provisioned.", "Die App benötigt Zugriff auf einen Dienst, den die Organisation nicht abonniert oder bereitgestellt hat.", "Check the API permissions; the resource must exist in the tenant.", "Die API-Berechtigungen prüfen; die Ressource muss im Mandanten existieren.")),
    (650056, e("MisconfiguredApplication", Config, Some(Consent), "The app has no permissions configured for the resource, or admin consent is missing.", "Für die Ressource sind keine Berechtigungen konfiguriert, oder die Administratorzustimmung fehlt.", "Add the permission and grant admin consent.", "Die Berechtigung hinzufügen und die Administratorzustimmung erteilen.")),
    (650057, e("InvalidResource", Config, Some(Consent), "The requested resource is not in the app's list of API permissions.", "Die angeforderte Ressource steht nicht in der Liste der API-Berechtigungen der App.", "Add the API to the app's permissions, or request scopes of an API that is configured.", "Die API zu den Berechtigungen der App hinzufügen oder Scopes einer konfigurierten API anfordern.")),
    (70000, e("InvalidGrant", Grant, None, "The grant (code or refresh token) is invalid: expired, revoked, for another client or with other scopes.", "Die Berechtigung (Code oder Refresh-Token) ist ungültig: abgelaufen, widerrufen, für einen anderen Client oder andere Scopes.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (70001, e("UnauthorizedClient", Config, Some(Tenant), "The application is disabled or not available in this tenant.", "Die Anwendung ist deaktiviert oder in diesem Mandanten nicht verfügbar.", "Check the client id and the tenant; enable the app.", "Client-ID und Mandanten prüfen; die App aktivieren.")),
    (70002, e("InvalidClient", Credential, Some(ClientCredentials), "The client credentials could not be validated.", "Die Client-Anmeldedaten konnten nicht validiert werden.", "Check secret/certificate and whether the app is registered as a confidential or a public client.", "Secret/Zertifikat prüfen und ob die App als vertraulicher oder öffentlicher Client registriert ist.")),
    (70003, e("UnsupportedGrantType", Config, Some(Flows), "The grant type is not supported for this app.", "Der Grant-Typ wird für diese App nicht unterstützt.", "Use a supported flow or enable it for the app.", "Einen unterstützten Flow verwenden oder ihn für die App aktivieren.")),
    (70007, e("UnsupportedResponseMode", Config, Some(Flows), "The response_mode is not supported for this response_type.", "Der response_mode wird für diesen response_type nicht unterstützt.", "Use response_mode=query for code, fragment or form_post for tokens.", "response_mode=query für code, fragment oder form_post für Tokens verwenden.")),
    (70008, e("ExpiredOrRevokedGrant", Grant, Some(Lifetime), "The authorization code or refresh token expired or was revoked (e.g. inactivity).", "Autorisierungscode oder Refresh-Token sind abgelaufen oder wurden widerrufen (z. B. Inaktivität).", "Redeem codes at once (they live about 10 minutes); for refresh tokens sign in again.", "Codes sofort einlösen (sie gelten etwa 10 Minuten); bei Refresh-Tokens erneut anmelden.")),
    (70011, e("InvalidScope", Config, Some(Consent), "The scope is invalid (unknown, malformed, a v1 resource mixed with v2 scopes, or .default combined with other scopes).", "Der Scope ist ungültig (unbekannt, fehlerhaft, v1-Ressource gemischt mit v2-Scopes oder .default mit anderen Scopes kombiniert).", "Request valid scopes, e.g. api://<app id>/<scope>, or <resource>/.default on its own.", "Gültige Scopes anfordern, z. B. api://<App-ID>/<Scope> oder <Ressource>/.default allein.")),
    (70016, e("AuthorizationPending", Normal, None, "Device flow: the user has not finished signing in yet — normal while the client polls.", "Gerätefluss: Der Benutzer hat die Anmeldung noch nicht abgeschlossen – normal, solange der Client abfragt.", "Nothing to do; poll at the interval the device code response names.", "Nichts zu tun; im Intervall der Gerätecode-Antwort abfragen.")),
    (70018, e("BadVerificationCode", Interaction, None, "Device flow: the user entered a wrong code.", "Gerätefluss: Der Benutzer hat einen falschen Code eingegeben.", "Let the user enter the code again.", "Den Benutzer den Code erneut eingeben lassen.")),
    (70019, e("CodeExpired", Interaction, None, "Device flow: the device code expired before the user signed in.", "Gerätefluss: Der Gerätecode ist abgelaufen, bevor sich der Benutzer angemeldet hat.", "Request a new device code; the user has about 15 minutes.", "Einen neuen Gerätecode anfordern; der Benutzer hat etwa 15 Minuten.")),
    (70043, e("BadTokenDueToSignInFrequency", Interaction, Some(Lifetime), "The refresh token expired because of a Conditional Access sign-in frequency.", "Das Refresh-Token ist wegen einer Anmeldehäufigkeit des bedingten Zugriffs abgelaufen.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (90002, e("InvalidTenantName", Config, Some(Tenant), "The tenant was not found (wrong tenant id or name in the authority).", "Der Mandant wurde nicht gefunden (falsche Mandanten-ID oder falscher Name in der Authority).", "Correct the tenant in the authority URL.", "Den Mandanten in der Authority-URL korrigieren.")),
    (90009, e("TokenForItselfMissingIdenticalAppIdentifier", Config, Some(Audience), "The app requests a token for itself; this works only with its GUID app id as resource.", "Die App fordert ein Token für sich selbst an; das geht nur mit ihrer GUID-App-ID als Ressource.", "Use the app id (GUID) or its Application ID URI as scope (<id>/.default).", "Die App-ID (GUID) oder ihre Application ID URI als Scope verwenden (<ID>/.default).")),
    (90014, e("MissingRequiredField", Config, None, "A required field is missing from the request.", "Im Request fehlt ein Pflichtfeld.", "Compare the request with the protocol (client_id, grant_type, redirect_uri, scope).", "Den Request mit dem Protokoll abgleichen (client_id, grant_type, redirect_uri, scope).")),
    (90072, e("PassThroughUserMfaError", User, Some(Tenant), "The external account does not exist in this tenant and cannot satisfy its MFA; it must be added as a guest.", "Das externe Konto existiert in diesem Mandanten nicht und kann dessen MFA nicht erfüllen; es muss als Gast hinzugefügt werden.", "Invite the user as a guest or sign in with an account of this tenant.", "Den Benutzer als Gast einladen oder mit einem Konto dieses Mandanten anmelden.")),
    (90094, e("AdminConsentRequired", Config, Some(Consent), "The permissions require administrator consent.", "Die Berechtigungen erfordern die Zustimmung eines Administrators.", "Have an administrator grant consent for the tenant.", "Einen Administrator die Zustimmung für den Mandanten erteilen lassen.")),
    (900144, e("MissingParameter", Config, None, "A required parameter is missing from the request body (e.g. grant_type, client_id).", "Im Request-Body fehlt ein Pflichtparameter (z. B. grant_type, client_id).", "Send the parameter as application/x-www-form-urlencoded form data.", "Den Parameter als application/x-www-form-urlencoded-Formulardaten senden.")),
    (900971, e("NoReplyAddress", Config, Some(RedirectUri), "No redirect URI was sent or registered.", "Es wurde keine Redirect-URI gesendet oder registriert.", "Register a redirect URI and send it in the request.", "Eine Redirect-URI registrieren und im Request senden.")),
    (9002313, e("InvalidRequest", Config, None, "The request is malformed or contains invalid parameters.", "Der Request ist fehlerhaft oder enthält ungültige Parameter.", "Compare the parameters with a working request; check encoding and duplicates.", "Die Parameter mit einem funktionierenden Request vergleichen; Kodierung und Duplikate prüfen.")),
    (9002326, e("CrossOriginRedemptionSpaOnly", Config, Some(Cors), "The code was redeemed cross-origin (from a browser) but the redirect URI is not registered as a single-page application.", "Der Code wurde Cross-Origin (aus dem Browser) eingelöst, die Redirect-URI ist aber nicht als Single-Page-Application registriert.", "Register the redirect URI under the 'Single-page application' platform instead of 'Web'.", "Die Redirect-URI unter der Plattform „Single-Page-Anwendung“ statt „Web“ registrieren.")),
    (9002327, e("SpaTokensCrossOriginOnly", Config, Some(Cors), "Tokens for the single-page application type can only be redeemed cross-origin (from the browser), not from a server.", "Tokens für den Typ Single-Page-Application können nur Cross-Origin (aus dem Browser) eingelöst werden, nicht von einem Server.", "Redeem in the browser, or register the redirect URI as 'Web' for server-side redemption.", "Im Browser einlösen oder die Redirect-URI für serverseitiges Einlösen als „Web“ registrieren.")),
    (500011, e("InvalidResourceServicePrincipalNotFound", Config, Some(Audience), "The resource (API) has no service principal in the tenant: wrong App ID URI, or the API is not provisioned or consented there.", "Die Ressource (API) hat keinen Dienstprinzipal im Mandanten: falsche App ID URI, oder die API ist dort nicht bereitgestellt bzw. nicht zugestimmt.", "Check the scope/resource URI; consent the API in this tenant.", "Scope-/Ressourcen-URI prüfen; der API in diesem Mandanten zustimmen.")),
    (500021, e("TenantRestrictions", Policy, Some(AccessPolicy), "Tenant restrictions of the network proxy block access to this tenant.", "Mandanteneinschränkungen des Netzwerk-Proxys blockieren den Zugriff auf diesen Mandanten.", "Ask the network team to allow the tenant (Restrict-Access-To-Tenants header policy).", "Das Netzwerkteam bitten, den Mandanten zuzulassen (Restrict-Access-To-Tenants-Richtlinie).")),
    (500113, e("NoReplyAddressRegistered", Config, Some(RedirectUri), "No redirect URI is registered for the app.", "Für die App ist keine Redirect-URI registriert.", "Register the redirect URI the app uses.", "Die von der App verwendete Redirect-URI registrieren.")),
    (500133, e("AssertionNotInValidTimeRange", Token, None, "The assertion (on-behalf-of user token) is expired or not yet valid — often an expired user token or clock skew.", "Die Assertion (Benutzertoken bei On-Behalf-Of) ist abgelaufen oder noch nicht gültig – oft ein abgelaufenes Benutzertoken oder Uhrzeitabweichung.", "Pass a fresh user token; check the clocks (CLOCK-SKEW).", "Ein frisches Benutzertoken übergeben; die Uhren prüfen (CLOCK-SKEW).")),
    (700016, e("UnauthorizedClient_DoesNotMatchRequest", Config, Some(Tenant), "The application (client_id) was not found in the tenant: wrong client id, wrong tenant, or the app is not provisioned there.", "Die Anwendung (client_id) wurde im Mandanten nicht gefunden: falsche Client-ID, falscher Mandant oder die App ist dort nicht bereitgestellt.", "Check client id and tenant of the authority; for multi-tenant apps, consent in the user's tenant.", "Client-ID und Mandant der Authority prüfen; bei mandantenübergreifenden Apps im Mandanten des Benutzers zustimmen.")),
    (700024, e("ClientAssertionNotInValidTimeRange", Credential, Some(ClientCredentials), "The client assertion is expired or not yet valid (clock of the client).", "Die Client-Assertion ist abgelaufen oder noch nicht gültig (Uhr des Clients).", "Create assertions with current nbf/exp; synchronise the client's clock.", "Assertions mit aktuellem nbf/exp erzeugen; die Uhr des Clients synchronisieren.")),
    (700025, e("InvalidClientPublicClientWithCredential", Config, Some(ClientCredentials), "The client is public but sent a client secret or assertion.", "Der Client ist öffentlich, hat aber ein Client-Secret oder eine Assertion gesendet.", "Do not send credentials from a public client, or register the app as confidential (Web platform).", "Von einem öffentlichen Client keine Anmeldedaten senden oder die App als vertraulich registrieren (Plattform Web).")),
    (700027, e("ClientAssertionSignatureInvalid", Credential, Some(ClientCredentials), "The client assertion's signature could not be validated (certificate not registered, wrong key).", "Die Signatur der Client-Assertion konnte nicht validiert werden (Zertifikat nicht registriert, falscher Schlüssel).", "Upload the signing certificate to the app and set x5t/kid to it.", "Das Signaturzertifikat zur App hochladen und x5t/kid darauf setzen.")),
    (700051, e("ResponseTypeTokenNotEnabled", Config, Some(Flows), "The implicit flow (response_type token) is not enabled for the app.", "Der implizite Flow (response_type token) ist für die App nicht aktiviert.", "Use authorization code + PKCE; enable 'Access tokens' under implicit grant only if unavoidable.", "Authorization Code + PKCE verwenden; „Zugriffstoken“ beim impliziten Flow nur aktivieren, wenn unvermeidbar.")),
    (700054, e("ResponseTypeIdTokenNotEnabled", Config, Some(Flows), "ID tokens through the implicit/hybrid flow (response_type id_token) are not enabled for the app.", "ID-Tokens über den impliziten/hybriden Flow (response_type id_token) sind für die App nicht aktiviert.", "Enable 'ID tokens' for the app or switch to response_type=code.", "„ID-Token“ für die App aktivieren oder auf response_type=code umstellen.")),
    (700082, e("ExpiredOrRevokedGrantInactiveToken", Grant, Some(Lifetime), "The refresh token expired after inactivity (90 days by default).", "Das Refresh-Token ist nach Inaktivität abgelaufen (standardmäßig 90 Tage).", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    (700084, e("SpaRefreshTokenExpired", Grant, Some(Lifetime), "Refresh tokens of single-page apps have a fixed 24-hour lifetime; it expired.", "Refresh-Tokens von Single-Page-Apps haben eine feste Laufzeit von 24 Stunden; sie ist abgelaufen.", "Sign in again (silently while the IdP session lasts, else interactively).", "Erneut anmelden (still, solange die IdP-Sitzung besteht, sonst interaktiv).")),
    (7000112, e("UnauthorizedClientApplicationDisabled", Config, None, "The application is disabled.", "Die Anwendung ist deaktiviert.", "Enable the app (Enterprise applications → Properties → Enabled for users to sign-in).", "Die App aktivieren (Unternehmensanwendungen → Eigenschaften → Aktiviert für die Benutzeranmeldung).")),
    (7000215, e("InvalidClientSecretProvided", Credential, Some(ClientCredentials), "Invalid client secret — often the secret's ID was used instead of its value.", "Ungültiges Client-Secret – oft wurde die ID des Secrets statt seines Werts verwendet.", "Use the secret's Value (shown once when created); create a new secret if it is lost.", "Den Wert des Secrets verwenden (nur beim Anlegen sichtbar); bei Verlust ein neues Secret anlegen.")),
    (7000218, e("ClientCredentialsRequired", Config, Some(Flows), "The request needs client credentials: the app is confidential, or public client flows are disabled.", "Der Request braucht Client-Anmeldedaten: Die App ist vertraulich, oder Flows für öffentliche Clients sind deaktiviert.", "Send the client credentials, or enable 'Allow public client flows' for device code / ROPC.", "Die Client-Anmeldedaten senden oder „Öffentliche Clientflows zulassen“ für Gerätecode/ROPC aktivieren.")),
    (7000222, e("InvalidClientSecretExpiredKeysProvided", Credential, Some(ClientCredentials), "The client secret has expired.", "Das Client-Secret ist abgelaufen.", "Create a new secret, roll it out, and monitor secret expiry (or use a certificate / managed identity).", "Ein neues Secret anlegen und verteilen und den Ablauf überwachen (oder ein Zertifikat / eine verwaltete Identität verwenden).")),
    (1002016, e("TlsVersionNotSupported", Config, None, "The client uses TLS 1.0/1.1 or 3DES, which Entra ID no longer accepts.", "Der Client verwendet TLS 1.0/1.1 oder 3DES, was Entra ID nicht mehr akzeptiert.", "Enable TLS 1.2+ in the client's runtime (e.g. .NET Framework SchUseStrongCrypto).", "TLS 1.2+ in der Laufzeitumgebung des Clients aktivieren (z. B. .NET Framework SchUseStrongCrypto).")),
];

/// Standard OAuth 2 / OIDC / device flow / DPoP / resource server error codes.
pub const OAUTH_ERRORS: &[(&str, Entry)] = &[
    ("invalid_request", e("invalid_request", Config, None, "The request is missing a parameter, repeats one or is malformed.", "Dem Request fehlt ein Parameter, er wiederholt einen oder ist fehlerhaft.", "Read error_description and compare the request with the protocol.", "error_description lesen und den Request mit dem Protokoll abgleichen.")),
    ("invalid_client", e("invalid_client", Credential, Some(ClientCredentials), "Client authentication failed: unknown client, wrong secret or certificate, or the wrong authentication method.", "Die Client-Authentifizierung ist fehlgeschlagen: unbekannter Client, falsches Secret oder Zertifikat oder falsche Authentifizierungsmethode.", "Check client id, secret/certificate (expiry) and the method (client_secret_basic vs. client_secret_post).", "Client-ID, Secret/Zertifikat (Ablauf) und Methode (client_secret_basic vs. client_secret_post) prüfen.")),
    ("invalid_grant", e("invalid_grant", Grant, None, "The code or refresh token is invalid, expired, revoked, already used, issued to another client, or the redirect_uri / PKCE verifier does not match.", "Code oder Refresh-Token sind ungültig, abgelaufen, widerrufen, bereits verwendet, für einen anderen Client ausgestellt, oder redirect_uri / PKCE-Verifier passen nicht.", "Redeem codes once and at once with the same redirect_uri and code_verifier; on refresh failure sign in again.", "Codes einmal und sofort mit derselben redirect_uri und demselben code_verifier einlösen; schlägt die Erneuerung fehl, neu anmelden.")),
    ("unauthorized_client", e("unauthorized_client", Config, Some(Flows), "The client is not allowed to use this grant or response type.", "Der Client darf diesen Grant- oder Response-Typ nicht verwenden.", "Enable the flow for the client or use an allowed one.", "Den Flow für den Client aktivieren oder einen erlaubten verwenden.")),
    ("unsupported_grant_type", e("unsupported_grant_type", Config, Some(Flows), "The IdP does not support this grant type (or the body is not form-encoded).", "Der IdP unterstützt diesen Grant-Typ nicht (oder der Body ist nicht formularkodiert).", "Send grant_type as application/x-www-form-urlencoded and use a supported grant.", "grant_type als application/x-www-form-urlencoded senden und einen unterstützten Grant verwenden.")),
    ("unsupported_response_type", e("unsupported_response_type", Config, Some(Flows), "The IdP or the client does not allow this response_type.", "IdP oder Client erlauben diesen response_type nicht.", "Use response_type=code (with PKCE).", "response_type=code (mit PKCE) verwenden.")),
    ("invalid_scope", e("invalid_scope", Config, Some(Consent), "A requested scope is unknown, malformed or not allowed for the client.", "Ein angeforderter Scope ist unbekannt, fehlerhaft oder für den Client nicht erlaubt.", "Request only scopes defined at the IdP and allowed for the client.", "Nur beim IdP definierte und für den Client erlaubte Scopes anfordern.")),
    ("access_denied", e("access_denied", Interaction, Some(Consent), "The user or the IdP denied the request (cancelled, consent refused, policy).", "Benutzer oder IdP haben den Request abgelehnt (abgebrochen, Zustimmung verweigert, Richtlinie).", "Read error_description; check consent and access policies.", "error_description lesen; Zustimmung und Zugriffsrichtlinien prüfen.")),
    ("server_error", e("server_error", Transient, None, "The IdP had an internal error.", "Beim IdP trat ein interner Fehler auf.", "Retry later with back-off; report the trace id to the IdP operator if it persists.", "Später mit Back-off wiederholen; bleibt es, die Trace-ID dem Betreiber des IdP melden.")),
    ("temporarily_unavailable", e("temporarily_unavailable", Transient, None, "The IdP is overloaded or in maintenance.", "Der IdP ist überlastet oder in Wartung.", "Retry later with back-off.", "Später mit Back-off wiederholen.")),
    ("interaction_required", e("interaction_required", Interaction, Some(SilentRenew), "A silent request cannot complete: the user has to interact (MFA, consent, policy).", "Ein stiller Request kann nicht abgeschlossen werden: Der Benutzer muss handeln (MFA, Zustimmung, Richtlinie).", "Fall back to interactive sign-in.", "Auf die interaktive Anmeldung ausweichen.")),
    ("login_required", e("login_required", Interaction, Some(SilentRenew), "A silent request (prompt=none) found no session at the IdP.", "Ein stiller Request (prompt=none) fand beim IdP keine Sitzung.", "Fall back to interactive sign-in; check third-party cookie blocking for iframes.", "Auf die interaktive Anmeldung ausweichen; Blockierung von Drittanbieter-Cookies bei iframes prüfen.")),
    ("consent_required", e("consent_required", Interaction, Some(Consent), "A silent request needs consent first.", "Ein stiller Request braucht zuerst eine Zustimmung.", "Ask for consent interactively, or have an administrator consent for all users.", "Die Zustimmung interaktiv einholen oder einen Administrator für alle Benutzer zustimmen lassen.")),
    ("account_selection_required", e("account_selection_required", Interaction, None, "Several sessions exist; the user has to choose an account.", "Es bestehen mehrere Sitzungen; der Benutzer muss ein Konto wählen.", "Pass login_hint, or let the user choose interactively.", "login_hint mitgeben oder den Benutzer interaktiv wählen lassen.")),
    ("invalid_request_uri", e("invalid_request_uri", Config, None, "The request_uri (PAR / request object) is invalid or expired.", "Die request_uri (PAR / Request-Objekt) ist ungültig oder abgelaufen.", "Use the request_uri at once and only once.", "Die request_uri sofort und nur einmal verwenden.")),
    ("invalid_request_object", e("invalid_request_object", Config, None, "The signed request object is invalid.", "Das signierte Request-Objekt ist ungültig.", "Check the signature and claims of the request object.", "Signatur und Claims des Request-Objekts prüfen.")),
    ("invalid_target", e("invalid_target", Config, Some(Audience), "The requested resource (resource indicator) is invalid or not allowed.", "Die angeforderte Ressource (Resource Indicator) ist ungültig oder nicht erlaubt.", "Request a resource the client may access.", "Eine Ressource anfordern, auf die der Client zugreifen darf.")),
    ("invalid_token", e("invalid_token", Token, Some(Audience), "The API rejected the access token: expired, revoked, malformed, wrong audience or issuer, or a signature it cannot validate.", "Die API hat das Zugriffstoken abgelehnt: abgelaufen, widerrufen, fehlerhaft, falsche Audience oder falscher Aussteller, oder eine Signatur, die sie nicht prüfen kann.", "Compare the token's claims (aud, iss, exp) with the API's validation settings.", "Die Claims des Tokens (aud, iss, exp) mit den Validierungseinstellungen der API vergleichen.")),
    ("insufficient_scope", e("insufficient_scope", Token, Some(Consent), "The token lacks the scope or role the API requires.", "Dem Token fehlt der Scope oder die Rolle, die die API verlangt.", "Request the required scope (and consent to it) or assign the app role.", "Den benötigten Scope anfordern (und zustimmen) oder die App-Rolle zuweisen.")),
    ("authorization_pending", e("authorization_pending", Normal, None, "Device flow: the user has not finished signing in yet — normal while the client polls.", "Gerätefluss: Der Benutzer hat die Anmeldung noch nicht abgeschlossen – normal, solange der Client abfragt.", "Nothing to do; poll at the announced interval.", "Nichts zu tun; im angekündigten Intervall abfragen.")),
    ("slow_down", e("slow_down", Normal, None, "Device flow: the client polls faster than allowed.", "Gerätefluss: Der Client fragt schneller ab als erlaubt.", "Increase the polling interval by 5 seconds each time slow_down is returned.", "Das Abfrageintervall bei jedem slow_down um 5 Sekunden erhöhen.")),
    ("expired_token", e("expired_token", Interaction, None, "Device flow: the device code expired before the user signed in.", "Gerätefluss: Der Gerätecode ist abgelaufen, bevor sich der Benutzer angemeldet hat.", "Start a new device authorization.", "Eine neue Geräteautorisierung starten.")),
    ("invalid_dpop_proof", e("invalid_dpop_proof", Token, None, "The DPoP proof is invalid (htm/htu, iat, signature, or replayed).", "Der DPoP-Nachweis ist ungültig (htm/htu, iat, Signatur oder wiederverwendet).", "Create a fresh proof per request with the exact method and URL; check the client clock.", "Pro Request einen frischen Nachweis mit exakter Methode und URL erzeugen; die Uhr des Clients prüfen.")),
    ("use_dpop_nonce", e("use_dpop_nonce", Normal, None, "The server requires a DPoP nonce — the client retries with the nonce it got (normal).", "Der Server verlangt eine DPoP-Nonce – der Client wiederholt mit der erhaltenen Nonce (normal).", "Nothing to do unless retries fail; cache the latest nonce per server.", "Nichts zu tun, solange die Wiederholung gelingt; die letzte Nonce pro Server cachen.")),
    ("unsupported_token_type", e("unsupported_token_type", Config, None, "The revocation endpoint does not support this token type.", "Der Widerrufs-Endpunkt unterstützt diesen Token-Typ nicht.", "Revoke refresh tokens, or use the supported token_type_hint.", "Refresh-Tokens widerrufen oder den unterstützten token_type_hint verwenden.")),
];

/// Keycloak `error_description` texts (lower-case substring, explanation).
pub const KEYCLOAK: &[(&str, Entry)] = &[
    ("invalid redirect uri", e("Invalid redirect uri", Config, Some(RedirectUri), "The redirect_uri is not in the client's Valid redirect URIs.", "Die redirect_uri steht nicht in den Valid redirect URIs des Clients.", "Add the exact URI (wildcards only at the end).", "Die exakte URI eintragen (Wildcards nur am Ende).")),
    ("invalid parameter: redirect_uri", e("Invalid parameter: redirect_uri", Config, Some(RedirectUri), "The redirect_uri is not in the client's Valid redirect URIs.", "Die redirect_uri steht nicht in den Valid redirect URIs des Clients.", "Add the exact URI (wildcards only at the end).", "Die exakte URI eintragen (Wildcards nur am Ende).")),
    ("code not valid", e("Code not valid", Grant, None, "The code was already used, expired, or belongs to another client or session.", "Der Code wurde bereits verwendet, ist abgelaufen oder gehört zu einem anderen Client oder einer anderen Sitzung.", "Redeem each code once and at once (default lifespan 1 minute: Realm settings → Tokens → Client login timeout).", "Jeden Code einmal und sofort einlösen (Standard 1 Minute: Realm settings → Tokens → Client login timeout).")),
    ("pkce verification failed", e("PKCE verification failed", Grant, Some(Pkce), "The code_verifier does not match the code_challenge.", "Der code_verifier passt nicht zur code_challenge.", "Send the verifier of this very authorization request.", "Den Verifier genau dieses Autorisierungs-Requests senden.")),
    ("client session not active", e("Client session not active", Grant, Some(Lifetime), "The client session at Keycloak ended (Client session idle / max).", "Die Client-Sitzung bei Keycloak ist beendet (Client session idle / max).", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    ("offline session not active", e("Offline session not active", Grant, Some(Lifetime), "The offline session expired (Offline Session Idle) or was revoked.", "Die Offline-Sitzung ist abgelaufen (Offline Session Idle) oder wurde widerrufen.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    ("session not active", e("Session not active", Grant, Some(Lifetime), "The user's SSO session ended (SSO Session Idle/Max, logout, or a restart without persistent sessions).", "Die SSO-Sitzung des Benutzers ist beendet (SSO Session Idle/Max, Abmeldung oder Neustart ohne persistente Sitzungen).", "Sign in again; align token refresh with SSO Session Idle.", "Erneut anmelden; die Token-Erneuerung auf SSO Session Idle abstimmen.")),
    ("token is not active", e("Token is not active", Grant, Some(Lifetime), "The refresh token expired or its session ended.", "Das Refresh-Token ist abgelaufen oder seine Sitzung beendet.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    ("refresh token expired", e("Refresh token expired", Grant, Some(Lifetime), "The refresh token expired.", "Das Refresh-Token ist abgelaufen.", SIGN_IN_AGAIN_EN, SIGN_IN_AGAIN_DE)),
    ("stale token", e("Stale token", Grant, None, "The refresh token was issued before a not-before policy or was replaced by rotation (reuse).", "Das Refresh-Token wurde vor einer Not-Before-Richtlinie ausgestellt oder durch Rotation ersetzt (Wiederverwendung).", "Always use the latest refresh token; do not share one refresh token between instances.", "Immer das neueste Refresh-Token verwenden; ein Refresh-Token nicht zwischen Instanzen teilen.")),
    ("maximum allowed refresh token reuse exceeded", e("Maximum allowed refresh token reuse exceeded", Grant, None, "Refresh token rotation detected a reused refresh token.", "Die Refresh-Token-Rotation hat ein wiederverwendetes Refresh-Token erkannt.", "Use each refresh token once; serialise refreshes across tabs and instances.", "Jedes Refresh-Token einmal verwenden; Erneuerungen über Tabs und Instanzen hinweg serialisieren.")),
    ("client not allowed for direct access grants", e("Client not allowed for direct access grants", Config, Some(Flows), "The password grant (ROPC) is disabled for the client.", "Der Password-Grant (ROPC) ist für den Client deaktiviert.", "Use authorization code + PKCE; enable Direct access grants only if unavoidable.", "Authorization Code + PKCE verwenden; Direct access grants nur aktivieren, wenn unvermeidbar.")),
    ("invalid client credentials", e("Invalid client credentials", Credential, Some(ClientCredentials), "Wrong client secret or authenticator.", "Falsches Client-Secret oder falscher Authenticator.", "Check the secret (Clients → <client> → Credentials) and Client authentication On.", "Das Secret prüfen (Clients → <client> → Credentials) und Client authentication On.")),
    ("invalid client or invalid client credentials", e("Invalid client or Invalid client credentials", Credential, Some(ClientCredentials), "Unknown client in this realm or wrong secret.", "Unbekannter Client in diesem Realm oder falsches Secret.", "Check client id, realm and secret.", "Client-ID, Realm und Secret prüfen.")),
    ("client secret not provided", e("Client secret not provided in request", Config, Some(ClientCredentials), "The client is confidential but the request carried no secret.", "Der Client ist vertraulich, der Request enthielt aber kein Secret.", "Send the secret, or make the client public (Client authentication Off) with PKCE.", "Das Secret senden oder den Client öffentlich machen (Client authentication Off) mit PKCE.")),
    ("public client not allowed to retrieve service account", e("Public client not allowed to retrieve service account", Config, Some(Flows), "Client credentials need a confidential client with service accounts enabled.", "Client Credentials brauchen einen vertraulichen Client mit aktivierten Service Accounts.", "Turn on Client authentication and Service accounts roles.", "Client authentication und Service accounts roles einschalten.")),
    ("account is not fully set up", e("Account is not fully set up", User, None, "The user has pending required actions (update password, verify e-mail, configure OTP).", "Beim Benutzer stehen Pflichtaktionen aus (Passwort ändern, E-Mail bestätigen, OTP einrichten).", "Let the user sign in interactively once, or clear the required actions (Users → <user>).", "Den Benutzer einmal interaktiv anmelden lassen oder die Pflichtaktionen entfernen (Users → <user>).")),
    ("invalid user credentials", e("Invalid user credentials", User, None, "Wrong user name or password.", "Falscher Benutzername oder falsches Passwort.", "Check the credentials; brute force detection may lock the user.", "Die Anmeldedaten prüfen; die Brute-Force-Erkennung kann den Benutzer sperren.")),
    ("account disabled", e("Account disabled", User, None, "The user account is disabled (or temporarily locked by brute force detection).", "Das Benutzerkonto ist deaktiviert (oder durch die Brute-Force-Erkennung vorübergehend gesperrt).", "Enable or unlock the user.", "Den Benutzer aktivieren oder entsperren.")),
];

pub fn aadsts(code: u32) -> Option<&'static Entry> {
    AADSTS.iter().find(|(c, _)| *c == code).map(|(_, e)| e)
}

pub fn oauth_error(code: &str) -> Option<&'static Entry> {
    OAUTH_ERRORS.iter().find(|(c, _)| c.eq_ignore_ascii_case(code.trim())).map(|(_, e)| e)
}

/// The Keycloak explanation of an `error_description`, if it is one of the known texts.
pub fn keycloak(description: &str) -> Option<&'static Entry> {
    let d = description.to_ascii_lowercase();
    KEYCLOAK.iter().find(|(k, _)| d.contains(k)).map(|(_, e)| e)
}

/// The most specific explanation: AADSTS code > Keycloak text > OAuth error code.
pub fn explain(idp: Idp, error: &str, description: Option<&str>, codes: &[u32]) -> Option<&'static Entry> {
    codes
        .iter()
        .find_map(|&c| aadsts(c))
        .or_else(|| description.filter(|_| matches!(idp, Idp::Keycloak | Idp::Generic)).and_then(keycloak))
        .or_else(|| oauth_error(error))
}

/// AADSTS numbers in a text (`AADSTS50011: …`).
pub fn aadsts_in(text: &str) -> Vec<u32> {
    let mut out = vec![];
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(p) = text[i..].find("AADSTS") {
        let start = i + p + 6;
        let end = b[start..].iter().position(|c| !c.is_ascii_digit()).map(|k| start + k).unwrap_or(b.len());
        if let Ok(n) = text[start..end].parse::<u32>()
            && !out.contains(&n)
        {
            out.push(n);
        }
        i = end.max(start);
        if i >= text.len() {
            break;
        }
    }
    out
}

// ------------------------------------------------------------------ resource server texts

/// Cause named by a resource server's `error_description`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceCause {
    Expired,
    NotYetValid,
    Audience,
    Issuer,
    Signature,
}

/// The cause in an API's `error_description` (ASP.NET Core `IDX…` messages, Spring, Node
/// libraries and similar wording).
pub fn resource_cause(description: &str) -> Option<ResourceCause> {
    let d = description.to_ascii_lowercase();
    let has = |w: &[&str]| w.iter().any(|x| d.contains(x));
    if has(&["idx10222", "not yet valid", "nbf", "used before"]) {
        Some(ResourceCause::NotYetValid)
    } else if has(&["idx10223", "expired", "lifetime validation failed", "token is expired", "jwt expired"]) {
        Some(ResourceCause::Expired)
    } else if has(&["idx10214", "idx10208", "audience", "aud claim", "jwt audience invalid"]) {
        Some(ResourceCause::Audience)
    } else if has(&["idx10205", "idx10204", "issuer", "iss claim", "jwt issuer invalid"]) {
        Some(ResourceCause::Issuer)
    } else if has(&["idx10501", "idx10503", "idx10511", "idx10500", "signature", "kid", "signing key"]) {
        Some(ResourceCause::Signature)
    } else {
        None
    }
}

/// Microsoft first-party resources: (app id, resource URI, host suffix of the API).
pub const MS_RESOURCES: &[(&str, &str, &str)] = &[
    ("00000003-0000-0000-c000-000000000000", "https://graph.microsoft.com", "graph.microsoft.com"),
    ("00000002-0000-0000-c000-000000000000", "https://graph.windows.net", "graph.windows.net"),
    ("00000003-0000-0ff1-ce00-000000000000", "https://microsoft.sharepoint-df.com", ".sharepoint.com"),
    ("00000002-0000-0ff1-ce00-000000000000", "https://outlook.office365.com", "outlook.office365.com"),
    ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "https://management.azure.com", "management.azure.com"),
    ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "https://management.core.windows.net", "management.azure.com"),
    ("e406a681-f3d4-42a8-90b6-c2b029497af1", "https://storage.azure.com", ".core.windows.net"),
    ("cfa8b339-82a2-471a-a3c9-0fc0be7a4093", "https://vault.azure.net", ".vault.azure.net"),
    ("022907d3-0f1b-48f7-badc-1ba6abab6d66", "https://database.windows.net", ".database.windows.net"),
];

/// The Microsoft first-party API an audience names (`https://graph.microsoft.com`, its app
/// id …): its host suffix.
pub fn ms_resource_host(aud: &str) -> Option<&'static str> {
    let a = aud.trim_end_matches('/');
    MS_RESOURCES.iter().find(|(id, uri, _)| a.eq_ignore_ascii_case(id) || a.eq_ignore_ascii_case(uri.trim_end_matches('/'))).map(|(_, _, h)| *h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_identity_providers() {
        assert_eq!(detect("login.microsoftonline.com", "/contoso.onmicrosoft.com/oauth2/v2.0/token"), Some(Idp::Entra));
        assert_eq!(detect("contoso.b2clogin.com", "/x/oauth2/v2.0/authorize"), Some(Idp::EntraB2c));
        assert_eq!(detect("contoso.ciamlogin.com", "/x"), Some(Idp::EntraExternal));
        assert_eq!(detect("sso.example.com", "/realms/main/protocol/openid-connect/token"), Some(Idp::Keycloak));
        assert_eq!(detect("sso.example.com", "/auth/realms/main/.well-known/openid-configuration"), Some(Idp::Keycloak));
        assert_eq!(detect("fs.example.com", "/adfs/oauth2/token"), Some(Idp::Adfs));
        assert_eq!(detect("dev-1.okta.com", "/oauth2/default/v1/token"), Some(Idp::Okta));
        assert_eq!(detect("tenant.eu.auth0.com", "/oauth/token"), Some(Idp::Auth0));
        assert_eq!(detect("auth.example.amazoncognito.com", "/oauth2/token"), Some(Idp::Cognito));
        assert_eq!(detect("cognito-idp.eu-central-1.amazonaws.com", "/pool/.well-known/jwks.json"), Some(Idp::Cognito));
        assert_eq!(detect("oauth2.googleapis.com", "/token"), Some(Idp::Google));
        assert_eq!(detect("id.example.com", "/connect/token"), Some(Idp::Duende));
        assert_eq!(detect("pf.example.com", "/as/token.oauth2"), Some(Idp::Ping));
        assert_eq!(detect("id.example.com", "/oauth2/token"), Some(Idp::Generic));
        assert_eq!(detect("api.example.com", "/v1/orders"), None);
        assert_eq!(from_issuer("https://sts.windows.net/72f9/"), Idp::Entra);
        assert!(is_entra_v1_issuer("https://sts.windows.net/72f9/"));
        assert_eq!(from_issuer("https://sso.example.com/realms/main"), Idp::Keycloak);
        assert_eq!(from_issuer("https://id.example.com"), Idp::Generic);
        assert_eq!(tenant_or_realm(Idp::Keycloak, "/realms/main/protocol/openid-connect/token").as_deref(), Some("main"));
        assert_eq!(tenant_or_realm(Idp::Entra, "/contoso.onmicrosoft.com/oauth2/v2.0/token").as_deref(), Some("contoso.onmicrosoft.com"));
    }

    #[test]
    fn endpoint_kinds() {
        assert_eq!(endpoint("/tenant/oauth2/v2.0/token"), Endpoint::Token);
        assert_eq!(endpoint("/tenant/oauth2/v2.0/devicecode"), Endpoint::Device);
        assert_eq!(endpoint("/realms/x/protocol/openid-connect/auth"), Endpoint::Authorize);
        assert_eq!(endpoint("/realms/x/protocol/openid-connect/certs"), Endpoint::Jwks);
        assert_eq!(endpoint("/realms/x/protocol/openid-connect/token/introspect"), Endpoint::Introspect);
        assert_eq!(endpoint("/x/.well-known/openid-configuration"), Endpoint::Discovery);
        assert_eq!(endpoint("/common/discovery/v2.0/keys"), Endpoint::Jwks);
        assert_eq!(endpoint("/api/orders"), Endpoint::Other);
    }

    #[test]
    fn knowledge_lookups() {
        assert_eq!(aadsts(50011).map(|e| e.topic), Some(Some(Topic::RedirectUri)));
        assert_eq!(aadsts(7000222).map(|e| e.class), Some(Class::Credential));
        assert!(aadsts(1).is_none());
        assert_eq!(oauth_error("authorization_pending").map(|e| e.class), Some(Class::Normal));
        assert_eq!(keycloak("Code not valid").map(|e| e.class), Some(Class::Grant));
        assert_eq!(keycloak("Offline session not active").map(|e| e.name), Some("Offline session not active"));
        assert_eq!(aadsts_in("AADSTS50011: The redirect URI … AADSTS50011 again, AADSTS7000215"), vec![50011, 7000215]);
        assert!(aadsts_in("AADSTS").is_empty());
        assert_eq!(explain(Idp::Entra, "invalid_client", None, &[7000215]).map(|e| e.name), Some("InvalidClientSecretProvided"));
        assert_eq!(explain(Idp::Keycloak, "invalid_grant", Some("Session not active"), &[]).map(|e| e.name), Some("Session not active"));
        assert_eq!(resource_cause("Bearer error: IDX10223: Lifetime validation failed. The token is expired."), Some(ResourceCause::Expired));
        assert_eq!(resource_cause("The audience 'api://x' is invalid"), Some(ResourceCause::Audience));
        assert_eq!(resource_cause("The issuer 'https://sts.windows.net/x/' is invalid"), Some(ResourceCause::Issuer));
        assert_eq!(resource_cause("The signature key was not found"), Some(ResourceCause::Signature));
        assert_eq!(ms_resource_host("00000003-0000-0000-c000-000000000000"), Some("graph.microsoft.com"));
        assert_eq!(ms_resource_host("https://graph.microsoft.com/"), Some("graph.microsoft.com"));
        // Every AADSTS code once.
        let mut codes: Vec<u32> = AADSTS.iter().map(|(c, _)| *c).collect();
        codes.sort_unstable();
        let n = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), n);
        assert!(n >= 50, "{n} AADSTS codes");
        // Every topic of a known IdP has a place.
        assert!(where_to(Idp::Entra, Topic::RedirectUri).is_some());
        assert!(where_to(Idp::Keycloak, Topic::Lifetime).is_some());
    }
}
