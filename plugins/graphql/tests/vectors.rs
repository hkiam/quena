//! GraphQL decoder tests: examples from the GraphQL specification and GraphQL over HTTP
//! (graphql.org), real client request shapes (Apollo batching and persisted queries) and garbage.
use graphql::gql::{self, Decoder, definitions, detect, format_query, render};

// GraphQL spec §2.8 (fragments) and §5 example schema, as a client would send it.
const HERO_QUERY: &str = "query HeroNameAndFriends($episode: Episode = JEDI, $withFriends: Boolean!) { hero(episode: $episode) { name, friends @include(if: $withFriends) { name ... on Droid { primaryFunction } ...HumanFields } } } fragment HumanFields on Human { height(unit: FOOT) homePlanet }";

const HERO_FORMATTED: &str = "query HeroNameAndFriends($episode: Episode = JEDI, $withFriends: Boolean!) {
  hero(episode: $episode) {
    name
    friends @include(if: $withFriends) {
      name
      ... on Droid {
        primaryFunction
      }
      ...HumanFields
    }
  }
}

fragment HumanFields on Human {
  height(unit: FOOT)
  homePlanet
}";

// GraphQL spec §7.1.2 (response with a field error and partial data).
const SPEC_ERROR_RESPONSE: &str = r#"{
  "errors": [
    {
      "message": "Name for character with ID 1002 could not be fetched.",
      "locations": [{ "line": 6, "column": 7 }],
      "path": ["hero", "heroFriends", 1, "name"],
      "extensions": { "code": "CAN_NOT_FETCH_BY_ID", "timestamp": "Fri Feb 9 14:33:09 UTC 2018" }
    }
  ],
  "data": {
    "hero": {
      "name": "R2-D2",
      "heroFriends": [
        { "id": "1000", "name": "Luke Skywalker" },
        { "id": "1002", "name": null },
        { "id": "1003", "name": "Leia Organa" }
      ]
    }
  }
}"#;

fn json_request() -> String {
    // JSON string escaping of the document as clients send it.
    let q = HERO_QUERY.replace('"', "\\\"");
    format!(r#"{{"operationName":"HeroNameAndFriends","variables":{{"episode":"EMPIRE","withFriends":true}},"query":"{q}"}}"#)
}

#[test]
fn formats_spec_query() {
    assert_eq!(format_query(HERO_QUERY), HERO_FORMATTED);
    // Formatting is stable.
    assert_eq!(format_query(HERO_FORMATTED), HERO_FORMATTED);
}

#[test]
fn formats_values_and_missing_commas() {
    let q = r#"mutation{createReview(episode:JEDI review:{stars:5 commentary:"This is a great movie!" tags:["a" "b"]}){stars commentary}}"#;
    assert_eq!(
        format_query(q),
        "mutation {\n  createReview(episode: JEDI, review: {stars: 5, commentary: \"This is a great movie!\", tags: [\"a\", \"b\"]}) {\n    stars\n    commentary\n  }\n}"
    );
    let q = "# list repos\n{ viewer { login repositories(first: 10, orderBy: {field: STARGAZERS, direction: DESC}) { nodes { name } } } }";
    assert_eq!(
        format_query(q),
        "# list repos\n{\n  viewer {\n    login\n    repositories(first: 10, orderBy: {field: STARGAZERS, direction: DESC}) {\n      nodes {\n        name\n      }\n    }\n  }\n}"
    );
}

#[test]
fn formats_schema_definitions() {
    let sdl = "type Query { \"The hero\" hero(episode: Episode): Character @deprecated(reason: \"no\") } union SearchResult = Human | Droid scalar Date extend type Foo implements Bar & Baz { x: [Int!]! }";
    assert_eq!(
        format_query(sdl),
        "type Query {\n  \"The hero\"\n  hero(episode: Episode): Character @deprecated(reason: \"no\")\n}\n\nunion SearchResult = Human | Droid\n\nscalar Date\n\nextend type Foo implements Bar & Baz {\n  x: [Int!]!\n}"
    );
    let kinds: Vec<String> = definitions(sdl).iter().map(|d| format!("{} {}", d.kind, d.name.clone().unwrap_or_default())).collect();
    assert_eq!(kinds, ["type Query", "union SearchResult", "scalar Date", "extend type Foo"]);
}

#[test]
fn detection() {
    let req = json_request();
    assert_eq!(detect(Some("application/json"), req.as_bytes()), 95);
    assert_eq!(detect(Some("application/json; charset=utf-8"), b"{\"query\":\"\\n  query Q { a }\"}"), 95);
    assert_eq!(detect(Some("application/json"), b"[{\"query\":\"{ a }\"},{\"query\":\"{ b }\"}]"), 95);
    assert_eq!(detect(None, b"{\"query\": \"mutation M { a }\"}"), 95);
    assert_eq!(detect(Some("application/graphql"), b"{ a }"), 100);
    assert_eq!(detect(Some("application/graphql-response+json"), b"{}"), 100);
    let apq = br#"{"operationName":"Q","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}"#;
    assert_eq!(detect(Some("application/json"), apq), 85);
    assert_eq!(detect(Some("application/json"), SPEC_ERROR_RESPONSE.as_bytes()), 60);
    assert_eq!(detect(Some("application/json"), br#"{"data":{"viewer":{"__typename":"User","login":"x"}}}"#), 55);
    // Not GraphQL.
    assert_eq!(detect(Some("application/json"), br#"{"query":"red shoes","page":2}"#), 0);
    assert_eq!(detect(Some("application/json"), br#"{"data":{"id":1}}"#), 0);
    assert_eq!(detect(Some("application/json"), br#"{"errors":[{"message":"bad"}]}"#), 0);
    assert_eq!(detect(Some("text/html"), b"{\"query\":\"{ a }\"}"), 0);
    assert_eq!(detect(Some("application/json"), b"query { a }"), 0);
    assert_eq!(detect(None, b""), 0);
}

#[test]
fn json_request_output() {
    let out = render(Some("application/json"), json_request().as_bytes(), json_request().len() as u64).unwrap();
    let expected = format!(
        "Operation: query HeroNameAndFriends\nDocument: query HeroNameAndFriends, fragment HumanFields\n\n--- Query ---\n{HERO_FORMATTED}\n\n--- Variables ---\n{{\n  \"episode\": \"EMPIRE\",\n  \"withFriends\": true\n}}\n"
    );
    assert_eq!(out, expected);
}

#[test]
fn raw_graphql_body() {
    let out = render(Some("application/graphql"), b"{ me { name } }", 15).unwrap();
    assert_eq!(out, "Operation: query (anonymous)\n\n--- Query ---\n{\n  me {\n    name\n  }\n}\n");
    assert!(render(Some("application/graphql"), b"hello", 5).is_err());
}

#[test]
fn operation_name_selects_one_of_several() {
    let body = r#"{"query":"query A { a } mutation B { b }","operationName":"B","variables":"{\"x\":1}"}"#;
    let out = render(Some("application/json"), body.as_bytes(), body.len() as u64).unwrap();
    assert!(out.starts_with("Operation: mutation B\nDocument: query A, mutation B\n"), "{out}");
    // Stringified variables are shown as JSON.
    assert!(out.contains("--- Variables ---\n{\n  \"x\": 1\n}\n"), "{out}");
    let body = r#"{"query":"query A { a } query C { c }"}"#;
    let out = render(None, body.as_bytes(), body.len() as u64).unwrap();
    assert!(out.starts_with("Operation: none selected"), "{out}");
    let body = r#"{"query":"query A { a }","operationName":"Z"}"#;
    assert!(render(None, body.as_bytes(), 0).unwrap().starts_with("Operation: Z (operationName; not defined in the document)"));
}

#[test]
fn batched_requests_and_persisted_queries() {
    let body = r#"[{"operationName":"A","query":"query A { a }"},{"operationName":"B","query":"query B { b }","variables":{"n":2}}]"#;
    let out = render(Some("application/json"), body.as_bytes(), body.len() as u64).unwrap();
    assert!(out.starts_with("Batch of 2 requests\n\n=== Request 1 of 2 ===\nOperation: query A\n"), "{out}");
    assert!(out.contains("=== Request 2 of 2 ===\nOperation: query B\n"), "{out}");
    let apq = r#"{"operationName":"Q","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}"#;
    let out = render(Some("application/json"), apq.as_bytes(), 0).unwrap();
    assert!(out.starts_with("Operation: Q\nPersisted query ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38: the document is not sent"), "{out}");
    assert!(out.contains("--- Extensions ---"));
}

#[test]
fn response_errors_first() {
    let out = render(Some("application/json"), SPEC_ERROR_RESPONSE.as_bytes(), 0).unwrap();
    assert!(
        out.starts_with(
            "Response: 1 error, partial data\n\n--- Errors ---\n1. Name for character with ID 1002 could not be fetched.\n   at line 6, column 7\n   path: hero.heroFriends.1.name\n   extensions: {\"code\": \"CAN_NOT_FETCH_BY_ID\", \"timestamp\": \"Fri Feb 9 14:33:09 UTC 2018\"}\n\n--- Data ---\n{\n  \"hero\": {"
        ),
        "{out}"
    );
    let out = render(Some("application/graphql-response+json"), br#"{"data":null,"errors":[{"message":"Unauthorized"}]}"#, 0).unwrap();
    assert!(out.starts_with("Response: 1 error, data null\n"), "{out}");
    let out = render(None, br#"[{"data":{"a":1}},{"data":{"b":2}}]"#, 0).unwrap();
    assert!(out.starts_with("Batch of 2 responses\n"), "{out}");
}

#[test]
fn not_graphql_json() {
    assert!(render(Some("application/json"), br#"{"hello":"world"}"#, 0).is_err());
    assert!(render(Some("application/json"), b"[]", 0).is_err());
    assert!(render(Some("application/json"), br#"{"query": 42}"#, 0).is_err());
    assert!(render(Some("application/json"), b"{\"query\":\"{ a }\"} trailing", 0).is_err());
}

#[test]
fn streaming_and_truncation() {
    let body = json_request();
    let mut d = Decoder::new(Some("application/json".into()));
    for c in body.as_bytes().chunks(7) {
        assert_eq!(d.push(c).unwrap(), "");
    }
    assert_eq!(d.finish().unwrap(), render(Some("application/json"), body.as_bytes(), body.len() as u64).unwrap());

    // Large variables beyond the buffer limit: shown as far as they go.
    let big = format!(r#"{{"query":"mutation Upload($f: [Int!]!) {{ upload(data: $f) }}","variables":{{"f":[{}]}}}}"#, vec!["1234567"; 20_000].join(","));
    let mut d = Decoder::with_limit(Some("application/json".into()), 64 << 10);
    for c in big.as_bytes().chunks(8192) {
        d.push(c).unwrap();
    }
    let out = d.finish().unwrap();
    assert!(out.starts_with(&format!("Note: the body has {} bytes; only the first 65536 are shown.\nNote: the JSON is cut off", big.len())), "{}", &out[..200]);
    assert!(out.contains("Operation: mutation Upload\n"));
    assert_eq!(gql::MAX_BUFFER, 8 << 20);
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn mutations_never_panic() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    let req = json_request();
    for orig in [req.as_str(), SPEC_ERROR_RESPONSE, HERO_QUERY, "{\"query\":\"\\\"\\\"\\\"x\"}"] {
        for _ in 0..3000 {
            let mut d = orig.as_bytes().to_vec();
            for _ in 0..1 + rng.next() % 4 {
                let i = (rng.next() as usize) % d.len();
                match rng.next() % 3 {
                    0 => d[i] = b"{}()[]:\"\\,.$@!#\n x9-"[(rng.next() % 20) as usize],
                    1 => d[i] ^= 1 << (rng.next() % 8),
                    _ => d.truncate(i.max(1)),
                }
            }
            let r = std::panic::catch_unwind(|| {
                detect(Some("application/json"), &d);
                let _ = render(Some("application/json"), &d, d.len() as u64);
                let _ = render(Some("application/graphql"), &d, d.len() as u64);
            });
            assert!(r.is_ok(), "panic on {}", String::from_utf8_lossy(&d));
        }
    }
}

#[test]
fn deep_nesting_is_limited() {
    let deep = format!("{{\"query\":\"{{ a }}\",\"variables\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(render(Some("application/json"), deep.as_bytes(), 0).is_err());
    let q = "{".repeat(100_000);
    let out = render(Some("application/graphql"), q.as_bytes(), 0).unwrap();
    assert!(out.lines().all(|l| l.len() <= 100));
}
