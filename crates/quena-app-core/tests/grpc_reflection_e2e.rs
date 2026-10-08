//! gRPC with schemas: a captured call decodes with field names once the schema was fetched
//! from the server by reflection (v1 unimplemented → v1alpha, a dependency by file name).

use bytes::Bytes;
use http_body::Frame;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, Value};
use quena_app_core::dto::Part;
use quena_app_core::{AppCore, Paths};
use std::convert::Infallible;
use std::pin::Pin;
use std::process::Command;
use std::task::{Context, Poll};

/// A body of one data frame followed by trailers (gRPC status).
struct GrpcBody(Option<Bytes>, Option<http::HeaderMap>);

impl http_body::Body for GrpcBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(d) = self.0.take() {
            return Poll::Ready(Some(Ok(Frame::data(d))));
        }
        Poll::Ready(self.1.take().map(|t| Ok(Frame::trailers(t))))
    }
}

fn frame(msg: &[u8]) -> Vec<u8> {
    let mut f = vec![0];
    f.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    f.extend_from_slice(msg);
    f
}

fn bytes_field(n: u8, b: &[u8]) -> Vec<u8> {
    let mut m = vec![(n << 3) | 2];
    let mut len = b.len();
    while len >= 0x80 {
        m.push((len as u8) | 0x80);
        len >>= 7;
    }
    m.push(len as u8);
    m.extend_from_slice(b);
    m
}

/// The schemas the server knows, compiled from two files (shop imports money).
fn schema() -> prost_types::FileDescriptorSet {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("common")).unwrap();
    std::fs::write(dir.path().join("common/money.proto"), "syntax = \"proto3\"; package common; message Money { int64 cents = 1; }").unwrap();
    std::fs::write(
        dir.path().join("shop.proto"),
        "syntax = \"proto3\"; package shop; import \"common/money.proto\"; message Item { string name = 1; common.Money price = 2; } service Shop { rpc Get(Item) returns (Item); }",
    )
    .unwrap();
    protox::compile(["shop.proto"], [dir.path()]).unwrap()
}

fn item(pool: &DescriptorPool) -> Vec<u8> {
    let mut m = DynamicMessage::new(pool.get_message_by_name("shop.Item").unwrap());
    m.set_field_by_name("name", Value::String("flute".into()));
    let mut price = DynamicMessage::new(pool.get_message_by_name("common.Money").unwrap());
    price.set_field_by_name("cents", Value::I64(1999));
    m.set_field_by_name("price", Value::Message(price));
    m.encode_to_vec()
}

/// A gRPC server (HTTP/1.1 and h2c) with the shop service and v1alpha reflection only.
fn server(set: prost_types::FileDescriptorSet) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            loop {
                let (s, _) = l.accept().await.unwrap();
                let set = set.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let set = set.clone();
                        async move {
                            use http_body_util::BodyExt;
                            let path = req.uri().path().to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let mut trailers = http::HeaderMap::new();
                            let mut data = Vec::new();
                            let pool = DescriptorPool::from_file_descriptor_set(set.clone()).unwrap();
                            if path == "/shop.Shop/Get" {
                                data = frame(&item(&pool));
                                trailers.insert("grpc-status", "0".parse().unwrap());
                            } else if path == "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" {
                                let req = &body[5..];
                                let (field, value) = (req[0] >> 3, String::from_utf8_lossy(&req[2..]).into_owned());
                                // By symbol: only the service's file (the dependency is asked for by name).
                                let want = if field == 4 && value == "shop.Shop" {
                                    Some("shop.proto")
                                } else if field == 3 {
                                    Some(value.as_str())
                                } else {
                                    None
                                };
                                let file = want.and_then(|w| set.file.iter().find(|f| f.name() == w));
                                let resp = match file {
                                    Some(f) => bytes_field(4, &bytes_field(1, &f.encode_to_vec())),
                                    None => bytes_field(7, &[0x08, 0x05]),
                                };
                                data = frame(&resp);
                                trailers.insert("grpc-status", "0".parse().unwrap());
                            } else {
                                trailers.insert("grpc-status", "12".parse().unwrap());
                                trailers.insert("grpc-message", "unimplemented".parse().unwrap());
                            }
                            Ok::<_, Infallible>(
                                http::Response::builder().header("content-type", "application/grpc").body(GrpcBody(Some(Bytes::from(data)), Some(trailers))).unwrap(),
                            )
                        }
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
    });
    port
}

#[test]
fn reflection_names_the_fields_of_captured_calls() {
    let set = schema();
    let pool = DescriptorPool::from_file_descriptor_set(set.clone()).unwrap();
    let port = server(set);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("settings.json"), r#"{"proxy":{"port":0,"actAsSystemProxy":false,"captureOnStartup":false,"useSystemUpstream":false}}"#).unwrap();
    let core = AppCore::new(Paths::at(dir.path().to_path_buf()), quena_app_core::logbuf::LogBuffer::new(100)).unwrap();
    let engine = quena_app_core::engine::ProxyEngine::new(&core).unwrap();
    core.set_proxy_engine(engine.clone());
    core.start_capture().unwrap();
    let addr = engine.proxy.listen_addrs().into_iter().find(|a| a.is_ipv4()).unwrap();

    // A gRPC call through the proxy, captured.
    let req = dir.path().join("req.bin");
    std::fs::write(&req, frame(&item(&pool))).unwrap();
    let url = format!("http://127.0.0.1:{port}/shop.Shop/Get");
    let out = dir.path().join("resp.bin").display().to_string();
    let o = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "20",
            "-x",
            &format!("http://{addr}"),
            "-H",
            "Content-Type: application/grpc",
            "--data-binary",
            &format!("@{}", req.display()),
            "-o",
            &out,
            "-w",
            "%{http_code}",
            &url,
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stdout), "200", "{}", String::from_utf8_lossy(&o.stderr));
    let t = std::time::Instant::now();
    let id = loop {
        if let Some(id) = (1..20).find(|&i| core.capture().detail(i).is_some_and(|d| d.request.url.ends_with("/shop.Shop/Get") && d.response.is_some())) {
            break id;
        }
        assert!(t.elapsed().as_secs() < 10, "session not captured");
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    // Without a schema: numbers only.
    let g = core.grpc(id, Part::Response, None).unwrap();
    assert!(g.is_grpc);
    assert_eq!(g.method.as_deref(), Some("shop.Shop/Get"));
    assert!(g.messages[0].fields.iter().all(|f| f.name.is_none()));

    // Reflection is off by default: nothing is sent.
    assert!(core.grpc_reflect(id).unwrap_err().to_string().contains("off"));
    let mut s = core.settings();
    s.protobuf.reflection = true;
    core.update_settings(s).unwrap();
    let r = core.grpc_reflect(id).unwrap();
    assert_eq!(r.service, "shop.Shop");
    assert_eq!(r.files, vec!["shop.proto".to_string(), "common/money.proto".to_string()]);
    assert!(dir.path().join("protobuf-reflection/shop.Shop.pb").exists());

    // Now with names, also of the nested message from the dependency.
    let g = core.grpc(id, Part::Response, None).unwrap();
    let m = &g.messages[0];
    assert_eq!(m.message_type.as_deref(), Some("shop.Item"));
    assert_eq!(m.fields[0].name.as_deref(), Some("name"));
    assert_eq!(m.fields[1].type_name.as_deref(), Some("common.Money"));
    assert_eq!(m.fields[1].children[0].name.as_deref(), Some("cents"));
    let st = core.protobuf_status();
    assert_eq!(st.services, vec!["shop.Shop".to_string()]);
    assert_eq!(st.reflected, vec!["shop.Shop".to_string()]);
    assert!(st.message_types.contains(&"common.Money".to_string()));
    // The request decodes as the method's input type; a chosen type wins.
    let g = core.grpc(id, Part::Request, Some("common.Money")).unwrap();
    assert_eq!(g.messages[0].message_type.as_deref(), Some("common.Money"));
    core.shutdown();
}
