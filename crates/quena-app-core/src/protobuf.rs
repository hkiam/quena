//! Protobuf schemas for decoding gRPC and protobuf bodies with field names: `.proto` files
//! and folders from the settings (compiled with protox), plus descriptors a gRPC server
//! returned through server reflection (kept in the data folder).

use crate::settings::ProtobufSettings;
use anyhow::{Context, Result, anyhow};
use parking_lot::RwLock;
use prost::Message;
use prost_reflect::DescriptorPool;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// `.proto` files taken from one folder, at most.
const MAX_FILES: usize = 2000;
/// Folder depth searched for `.proto` files.
const MAX_DEPTH: usize = 8;

/// The compiled schemas, rebuilt when the settings change.
#[derive(Default)]
pub struct Schemas {
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    /// Settings and reflection cache generation the pool was built from.
    key: Option<(ProtobufSettings, u64)>,
    pool: Option<DescriptorPool>,
    error: Option<String>,
    files: usize,
}

/// What the schemas contain (Settings → Bodies → Protobuf schemas).
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SchemaStatus {
    /// `.proto` files compiled.
    pub files: usize,
    pub messages: usize,
    /// Services with their full names.
    pub services: Vec<String>,
    /// Message types by full name, sorted (for choosing the type of a plain protobuf body).
    pub message_types: Vec<String>,
    /// Files fetched from servers by reflection.
    pub reflected: Vec<String>,
    pub error: Option<String>,
}

/// Message types listed in the status.
const MAX_TYPES: usize = 5000;

/// The folder for descriptors fetched by server reflection.
pub fn reflection_dir(data: &Path) -> PathBuf {
    data.join("protobuf-reflection")
}

/// Changes whenever a reflection result is saved (part of the cache key).
fn reflection_generation(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
                .map(|t| t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0))
                .fold(0u64, |a, b| a.wrapping_add(b))
        })
        .unwrap_or(0)
}

impl Schemas {
    /// The descriptor pool for these settings (compiled once, then cached); `None` when no
    /// schema is configured or compiling failed (see [`Schemas::status`]).
    pub fn pool(&self, s: &ProtobufSettings, data: &Path) -> Option<DescriptorPool> {
        let generation = reflection_generation(&reflection_dir(data));
        let key = (s.clone(), generation);
        if self.state.read().key.as_ref() == Some(&key) {
            return self.state.read().pool.clone();
        }
        let mut st = self.state.write();
        match build(s, &reflection_dir(data)) {
            Ok((pool, files)) => {
                let any = pool.all_messages().len() > 0;
                st.pool = any.then_some(pool);
                st.error = None;
                st.files = files;
            }
            Err(e) => {
                tracing::warn!(target: "quena", "protobuf schemas: {e:#}");
                st.pool = None;
                st.error = Some(format!("{e:#}"));
                st.files = 0;
            }
        }
        st.key = Some(key);
        st.pool.clone()
    }

    pub fn status(&self, s: &ProtobufSettings, data: &Path) -> SchemaStatus {
        let pool = self.pool(s, data);
        let st = self.state.read();
        let reflected = std::fs::read_dir(reflection_dir(data))
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().trim_end_matches(".pb").to_string()).collect())
            .unwrap_or_default();
        SchemaStatus {
            files: st.files,
            messages: pool.as_ref().map(|p| p.all_messages().count()).unwrap_or(0),
            services: pool.as_ref().map(|p| p.services().map(|s| s.full_name().to_string()).collect()).unwrap_or_default(),
            message_types: pool
                .as_ref()
                .map(|p| {
                    let mut v: Vec<String> = p.all_messages().filter(|m| !m.is_map_entry()).map(|m| m.full_name().to_string()).collect();
                    v.sort();
                    v.truncate(MAX_TYPES);
                    v
                })
                .unwrap_or_default(),
            reflected,
            error: st.error.clone(),
        }
    }
}

/// `.proto` files of `paths` (files, or folders searched recursively) and the folders
/// imports are resolved against.
fn collect(paths: &[String], includes: &[String]) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut files = Vec::new();
    let mut inc: Vec<PathBuf> = includes.iter().map(|s| PathBuf::from(s.trim())).filter(|p| !p.as_os_str().is_empty()).collect();
    for p in paths.iter().map(|s| PathBuf::from(s.trim())).filter(|p| !p.as_os_str().is_empty()) {
        if p.is_dir() {
            let before = files.len();
            walk(&p, 0, &mut files);
            if files.len() - before >= MAX_FILES {
                tracing::warn!(target: "quena", "{}: only the first {MAX_FILES} .proto files are used", p.display());
            }
            inc.push(p);
        } else if p.is_file() {
            if let Some(parent) = p.parent() {
                inc.push(parent.to_path_buf());
            }
            files.push(p);
        } else {
            return Err(anyhow!("{}: no such file or folder", p.display()));
        }
    }
    inc.dedup();
    Ok((files, inc))
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, depth + 1, out);
        } else if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("proto")) && out.len() < MAX_FILES {
            out.push(p);
        }
    }
}

/// Compile the configured files and add the reflected descriptors.
fn build(s: &ProtobufSettings, reflected: &Path) -> Result<(DescriptorPool, usize)> {
    let (files, includes) = collect(&s.proto_paths, &s.include_paths)?;
    let mut pool = if files.is_empty() {
        DescriptorPool::new()
    } else {
        let mut c = protox::Compiler::new(&includes).map_err(|e| anyhow!("{e}"))?;
        c.include_imports(true);
        c.open_files(&files).map_err(|e| anyhow!("{e}"))?;
        c.descriptor_pool()
    };
    if let Ok(rd) = std::fs::read_dir(reflected) {
        for e in rd.filter_map(|e| e.ok()) {
            let bytes = std::fs::read(e.path()).with_context(|| e.path().display().to_string())?;
            let set = prost_types::FileDescriptorSet::decode(bytes.as_slice()).with_context(|| e.path().display().to_string())?;
            // Files that the .proto files define already are kept from there.
            let fresh: Vec<_> = set.file.into_iter().filter(|f| pool.get_file_by_name(f.name()).is_none()).collect();
            if let Err(err) = pool.add_file_descriptor_protos(fresh) {
                tracing::warn!(target: "quena", "{}: {err}", e.path().display());
            }
        }
    }
    Ok((pool, files.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_and_files_compile_with_imports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("protos/common")).unwrap();
        std::fs::write(dir.path().join("protos/common/money.proto"), "syntax = \"proto3\"; package common; message Money { int64 cents = 1; }").unwrap();
        std::fs::write(
            dir.path().join("protos/shop.proto"),
            "syntax = \"proto3\"; package shop; import \"common/money.proto\"; import \"google/protobuf/timestamp.proto\"; message Item { string name = 1; common.Money price = 2; google.protobuf.Timestamp at = 3; } service Shop { rpc Get(Item) returns (Item); }",
        )
        .unwrap();
        let s = ProtobufSettings { proto_paths: vec![dir.path().join("protos").display().to_string()], ..Default::default() };
        let schemas = Schemas::default();
        let st = schemas.status(&s, dir.path());
        assert_eq!(st.error, None);
        assert_eq!(st.files, 2);
        assert_eq!(st.services, vec!["shop.Shop".to_string()]);
        assert!(schemas.pool(&s, dir.path()).unwrap().get_message_by_name("common.Money").is_some());
        // A broken file is reported, not panicked on.
        std::fs::write(dir.path().join("protos/broken.proto"), "syntax = \"proto3\"; message {").unwrap();
        let s2 = ProtobufSettings { include_paths: vec!["x".into()], ..s.clone() };
        assert!(schemas.status(&s2, dir.path()).error.is_some());
        let missing = ProtobufSettings { proto_paths: vec!["/no/such/file.proto".into()], ..Default::default() };
        assert!(schemas.status(&missing, dir.path()).error.unwrap().contains("no such file"));
    }
}

// ------------------------------------------------------------------ server reflection

/// What [`crate::AppCore::grpc_reflect`] fetched.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reflected {
    pub service: String,
    /// `.proto` file names the server returned.
    pub files: Vec<String>,
}

/// A protobuf wire field: (number, wire type, varint value, bytes).
type WireField<'a> = (u64, u8, u64, &'a [u8]);

/// The wire fields of a message.
fn wire_fields(mut b: &[u8]) -> Option<Vec<WireField<'_>>> {
    fn varint(b: &mut &[u8]) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = b.split_first()?;
            *b = rest;
            v |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let tag = varint(&mut b)?;
        let (number, wire) = (tag >> 3, (tag & 7) as u8);
        match wire {
            0 => out.push((number, 0, varint(&mut b)?, &[][..])),
            2 => {
                let len = usize::try_from(varint(&mut b)?).ok()?;
                if b.len() < len {
                    return None;
                }
                let (v, rest) = b.split_at(len);
                b = rest;
                out.push((number, 2, 0, v));
            }
            1 => b = b.get(8..)?,
            5 => b = b.get(4..)?,
            _ => return None,
        }
    }
    Some(out)
}

/// A `ServerReflectionRequest` with one string field (`file_by_filename` = 3,
/// `file_containing_symbol` = 4).
fn reflection_request(field: u8, value: &str) -> Vec<u8> {
    let mut m = vec![(field << 3) | 2];
    let mut n = value.len();
    while n >= 0x80 {
        m.push((n as u8) | 0x80);
        n >>= 7;
    }
    m.push(n as u8);
    m.extend_from_slice(value.as_bytes());
    m
}

/// The `FileDescriptorProto`s of a `ServerReflectionResponse`, or its error.
fn reflection_files(resp: &[u8]) -> Result<Vec<prost_types::FileDescriptorProto>> {
    let fields = wire_fields(resp).ok_or_else(|| anyhow!("the server's reflection answer is not protobuf"))?;
    let mut files = Vec::new();
    for (n, _, _, bytes) in fields {
        match n {
            // file_descriptor_response { repeated bytes file_descriptor_proto = 1 }
            4 => {
                for (m, _, _, fd) in wire_fields(bytes).unwrap_or_default() {
                    if m == 1 {
                        files.push(prost_types::FileDescriptorProto::decode(fd).context("file descriptor")?);
                    }
                }
            }
            // error_response { int32 error_code = 1; string error_message = 2 }
            7 => {
                let e = wire_fields(bytes).unwrap_or_default();
                let code = e.iter().find(|f| f.0 == 1).map(|f| f.2).unwrap_or(0);
                let msg = e.iter().find(|f| f.0 == 2).map(|f| String::from_utf8_lossy(f.3).into_owned()).unwrap_or_default();
                return Err(anyhow!("the server's reflection: error {code}: {msg}"));
            }
            _ => {}
        }
    }
    Ok(files)
}

impl crate::AppCore {
    /// Fetch the schema of a gRPC session's service from its server (gRPC server
    /// reflection, v1 or v1alpha) and keep it, so the session and later ones decode with
    /// field names. Sends a request to that server: only on the user's request, and only
    /// when switched on in the settings.
    pub fn grpc_reflect(&self, id: quena_model::SessionId) -> Result<Reflected> {
        if !self.settings().protobuf.reflection {
            return Err(anyhow!("server reflection is off (Settings → Bodies & Storage → Protobuf schemas)"));
        }
        let d = self.capture().detail(id).ok_or_else(|| anyhow!("session #{id} not found"))?;
        let uri: http::Uri = d.request.url.parse().context("session URL")?;
        let path = uri.path().trim_start_matches('/');
        let service = path.rsplit_once('/').map(|(s, _)| s.to_string()).filter(|s| !s.is_empty()).ok_or_else(|| anyhow!("the URL names no gRPC service"))?;
        let origin = format!("{}://{}", uri.scheme_str().unwrap_or("http"), uri.authority().map(|a| a.as_str()).unwrap_or(""));
        let engine = self.proxy_engine()?;
        let shared = engine.proxy.shared.clone();
        let rt = engine.proxy.runtime().handle().clone();
        // Run on the proxy's runtime and wait here (this may itself be a runtime thread).
        let call = |api: &str, req: Vec<u8>| {
            let url = format!("{origin}/grpc.reflection.{api}.ServerReflection/ServerReflectionInfo");
            let (tx, rx) = std::sync::mpsc::channel();
            let shared = shared.clone();
            rt.spawn(async move {
                let _ = tx.send(quena_proxy::grpc_client::call(&shared, &url, &req).await);
            });
            rx.recv_timeout(std::time::Duration::from_secs(45)).unwrap_or_else(|_| Err(quena_proxy::grpc_client::GrpcError::Other("no answer".into())))
        };
        // v1 first; servers that only have v1alpha say UNIMPLEMENTED (12).
        let mut api = "v1";
        let first = match call(api, reflection_request(4, &service)) {
            Err(quena_proxy::grpc_client::GrpcError::Status(12, _)) => {
                api = "v1alpha";
                call(api, reflection_request(4, &service))
            }
            other => other,
        }
        .map_err(|e| anyhow!("{e}"))?;
        let mut files: Vec<prost_types::FileDescriptorProto> = Vec::new();
        for m in &first {
            files.extend(reflection_files(m)?);
        }
        // Dependencies the server did not include: ask for them by file name.
        for _ in 0..50 {
            let have: Vec<String> = files.iter().map(|f| f.name().to_string()).collect();
            let Some(missing) = files.iter().flat_map(|f| f.dependency.iter()).find(|d| !have.contains(d)).cloned() else {
                break;
            };
            let answer = call(api, reflection_request(3, &missing)).map_err(|e| anyhow!("{e}"))?;
            let before = files.len();
            for m in &answer {
                files.extend(reflection_files(m)?.into_iter().filter(|f| !have.contains(&f.name().to_string())));
            }
            if files.len() == before {
                return Err(anyhow!("the server did not return {missing}"));
            }
        }
        if files.is_empty() {
            return Err(anyhow!("the server returned no schema for {service}"));
        }
        // Check that the files fit together before keeping them.
        let mut pool = DescriptorPool::new();
        pool.add_file_descriptor_protos(files.clone()).map_err(|e| anyhow!("the server's schema is incomplete: {e}"))?;
        let dir = reflection_dir(&self.paths.data);
        std::fs::create_dir_all(&dir)?;
        let name: String = service.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '_' }).collect();
        let set = prost_types::FileDescriptorSet { file: files.clone() };
        std::fs::write(dir.join(format!("{name}.pb")), set.encode_to_vec())?;
        tracing::info!(target: "quena", "schema of {service} fetched by server reflection ({} file(s))", files.len());
        Ok(Reflected { service, files: files.iter().map(|f| f.name().to_string()).collect() })
    }

    /// The protobuf schemas (`.proto` files, reflection) and whether they compile.
    pub fn protobuf_status(&self) -> SchemaStatus {
        self.protobuf.status(&self.settings().protobuf, &self.paths.data)
    }
}
