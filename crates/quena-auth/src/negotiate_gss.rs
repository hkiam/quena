//! Negotiate/Kerberos (SPNEGO) via GSS-API on macOS and Linux. SSO with an existing
//! Kerberos ticket; no ticket → NoCredentials so the caller falls back (NTLM).
//!
//! Backend: macOS links GSS.framework directly. Linux loads MIT (`libgssapi_krb5`)
//! or Heimdal (`libgssapi`) at runtime, so the app builds and starts without Kerberos
//! packages; a missing library → Unsupported (same fallback). Both share the C ABI
//! below (MIT/Heimdal/GSS.framework all use `gss_OID_desc { OM_uint32; void * }`).

#![allow(non_camel_case_types)]

use crate::AuthError;
use std::ffi::c_void;

#[repr(C)]
struct GssBufferDesc {
    length: usize,
    value: *mut c_void,
}

#[repr(C)]
struct GssOidDesc {
    length: u32,
    elements: *const c_void,
}

type OM_uint32 = u32;

// SPNEGO mech OID 1.3.6.1.5.5.2
static SPNEGO_OID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
// gss_nt_hostbased_service OID 1.2.840.113554.1.2.1.4
static HOSTBASED_OID: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

const GSS_S_COMPLETE: OM_uint32 = 0;
const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;

type ImportNameFn = unsafe extern "C" fn(
    minor: *mut OM_uint32,
    input: *const GssBufferDesc,
    name_type: *const GssOidDesc,
    output: *mut *mut c_void,
) -> OM_uint32;
type InitSecContextFn = unsafe extern "C" fn(
    minor: *mut OM_uint32,
    cred: *const c_void,
    ctx: *mut *mut c_void,
    target: *const c_void,
    mech: *const GssOidDesc,
    req_flags: OM_uint32,
    time_req: OM_uint32,
    chan: *const c_void,
    input_token: *const GssBufferDesc,
    actual_mech: *mut *const GssOidDesc,
    output_token: *mut GssBufferDesc,
    ret_flags: *mut OM_uint32,
    time_rec: *mut OM_uint32,
) -> OM_uint32;
type ReleaseNameFn =
    unsafe extern "C" fn(minor: *mut OM_uint32, name: *mut *mut c_void) -> OM_uint32;
type ReleaseBufferFn =
    unsafe extern "C" fn(minor: *mut OM_uint32, buf: *mut GssBufferDesc) -> OM_uint32;
type DeleteSecContextFn = unsafe extern "C" fn(
    minor: *mut OM_uint32,
    ctx: *mut *mut c_void,
    out: *mut GssBufferDesc,
) -> OM_uint32;

/// The GSS-API entry points we use, from whichever backend the platform has.
struct Gss {
    import_name: ImportNameFn,
    init_sec_context: InitSecContextFn,
    release_name: ReleaseNameFn,
    release_buffer: ReleaseBufferFn,
    delete_sec_context: DeleteSecContextFn,
}

#[cfg(target_os = "macos")]
mod backend {
    use super::*;

    #[link(name = "GSS", kind = "framework")]
    unsafe extern "C" {
        fn gss_import_name(
            minor: *mut OM_uint32,
            input: *const GssBufferDesc,
            name_type: *const GssOidDesc,
            output: *mut *mut c_void,
        ) -> OM_uint32;
        fn gss_init_sec_context(
            minor: *mut OM_uint32,
            cred: *const c_void,
            ctx: *mut *mut c_void,
            target: *const c_void,
            mech: *const GssOidDesc,
            req_flags: OM_uint32,
            time_req: OM_uint32,
            chan: *const c_void,
            input_token: *const GssBufferDesc,
            actual_mech: *mut *const GssOidDesc,
            output_token: *mut GssBufferDesc,
            ret_flags: *mut OM_uint32,
            time_rec: *mut OM_uint32,
        ) -> OM_uint32;
        fn gss_release_name(minor: *mut OM_uint32, name: *mut *mut c_void) -> OM_uint32;
        fn gss_release_buffer(minor: *mut OM_uint32, buf: *mut GssBufferDesc) -> OM_uint32;
        fn gss_delete_sec_context(
            minor: *mut OM_uint32,
            ctx: *mut *mut c_void,
            out: *mut GssBufferDesc,
        ) -> OM_uint32;
    }

    static GSS: Gss = Gss {
        import_name: gss_import_name,
        init_sec_context: gss_init_sec_context,
        release_name: gss_release_name,
        release_buffer: gss_release_buffer,
        delete_sec_context: gss_delete_sec_context,
    };

    pub(super) fn gss() -> Result<&'static Gss, AuthError> {
        Ok(&GSS)
    }
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;
    use std::sync::OnceLock;

    /// MIT first (the common default), then Heimdal.
    pub(super) const CANDIDATES: &[&str] = &[
        "libgssapi_krb5.so.2",
        "libgssapi_krb5.so",
        "libgssapi.so.3",
        "libgssapi.so",
    ];

    // The Library stays alive for the process lifetime alongside its function table.
    static LOADED: OnceLock<Result<(libloading::Library, Gss), String>> = OnceLock::new();

    pub(super) fn gss() -> Result<&'static Gss, AuthError> {
        match LOADED.get_or_init(|| load(CANDIDATES)) {
            Ok((_, gss)) => Ok(gss),
            Err(e) => {
                tracing::debug!(target: "quena::auth", "Negotiate unavailable: {e}");
                Err(AuthError::Unsupported)
            }
        }
    }

    pub(super) fn load(candidates: &[&str]) -> Result<(libloading::Library, Gss), String> {
        let mut last = String::from("no candidates");
        for name in candidates {
            // SAFETY: GSS-API libraries have no unsound initialisers; we only resolve symbols.
            let lib = match unsafe { libloading::Library::new(name) } {
                Ok(l) => l,
                Err(e) => {
                    last = format!("{name}: {e}");
                    continue;
                }
            };
            match unsafe { resolve(&lib) } {
                Ok(gss) => {
                    tracing::debug!(target: "quena::auth", "Negotiate: loaded {name}");
                    return Ok((lib, gss));
                }
                Err(e) => last = format!("{name}: {e}"),
            }
        }
        Err(format!("no GSS-API library found ({last})"))
    }

    unsafe fn resolve(lib: &libloading::Library) -> Result<Gss, libloading::Error> {
        unsafe {
            Ok(Gss {
                import_name: *lib.get::<ImportNameFn>(b"gss_import_name\0")?,
                init_sec_context: *lib.get::<InitSecContextFn>(b"gss_init_sec_context\0")?,
                release_name: *lib.get::<ReleaseNameFn>(b"gss_release_name\0")?,
                release_buffer: *lib.get::<ReleaseBufferFn>(b"gss_release_buffer\0")?,
                delete_sec_context: *lib.get::<DeleteSecContextFn>(b"gss_delete_sec_context\0")?,
            })
        }
    }
}

pub struct NegotiateCtx {
    gss: &'static Gss,
    ctx: *mut c_void,
    target: *mut c_void,
    complete: bool,
}

unsafe impl Send for NegotiateCtx {}

impl NegotiateCtx {
    pub fn new(host: &str) -> Result<NegotiateCtx, AuthError> {
        let gss = backend::gss()?;
        let spn = format!("HTTP@{host}");
        let mut buf = GssBufferDesc {
            length: spn.len(),
            value: spn.as_ptr() as *mut c_void,
        };
        let name_oid = GssOidDesc {
            length: HOSTBASED_OID.len() as u32,
            elements: HOSTBASED_OID.as_ptr() as *const c_void,
        };
        let mut minor = 0;
        let mut target: *mut c_void = std::ptr::null_mut();
        let major = unsafe { (gss.import_name)(&mut minor, &mut buf, &name_oid, &mut target) };
        if major != GSS_S_COMPLETE {
            return Err(AuthError::Other(format!(
                "gss_import_name failed (0x{major:x})"
            )));
        }
        Ok(NegotiateCtx {
            gss,
            ctx: std::ptr::null_mut(),
            target,
            complete: false,
        })
    }

    pub fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        if self.complete {
            return Err(AuthError::Protocol(
                "Negotiate handshake already complete".into(),
            ));
        }
        let mech = GssOidDesc {
            length: SPNEGO_OID.len() as u32,
            elements: SPNEGO_OID.as_ptr() as *const c_void,
        };
        let in_buf = input.map(|d| GssBufferDesc {
            length: d.len(),
            value: d.as_ptr() as *mut c_void,
        });
        let in_ptr = in_buf
            .as_ref()
            .map(|b| b as *const GssBufferDesc)
            .unwrap_or(std::ptr::null());
        let mut out = GssBufferDesc {
            length: 0,
            value: std::ptr::null_mut(),
        };
        let mut minor = 0;
        let mut ret_flags = 0;
        let major = unsafe {
            (self.gss.init_sec_context)(
                &mut minor,
                std::ptr::null(),
                &mut self.ctx,
                self.target,
                &mech,
                GSS_C_MUTUAL_FLAG,
                0,
                std::ptr::null(),
                in_ptr,
                std::ptr::null_mut(),
                &mut out,
                &mut ret_flags,
                std::ptr::null_mut(),
            )
        };
        if major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED {
            // 0x70000 range: no credentials / no ticket.
            tracing::debug!(target: "quena::auth", "gss_init_sec_context failed (major 0x{major:x}, minor 0x{minor:x})");
            if !out.value.is_null() {
                unsafe { (self.gss.release_buffer)(&mut minor, &mut out) };
            }
            return Err(AuthError::NoCredentials);
        }
        self.complete = major == GSS_S_COMPLETE;
        let token = if out.length > 0 {
            let slice =
                unsafe { std::slice::from_raw_parts(out.value as *const u8, out.length) }.to_vec();
            unsafe { (self.gss.release_buffer)(&mut minor, &mut out) };
            slice
        } else {
            Vec::new()
        };
        Ok(token)
    }
}

impl Drop for NegotiateCtx {
    fn drop(&mut self) {
        let mut minor = 0;
        let mut out = GssBufferDesc {
            length: 0,
            value: std::ptr::null_mut(),
        };
        unsafe {
            if !self.ctx.is_null() {
                (self.gss.delete_sec_context)(&mut minor, &mut self.ctx, &mut out);
            }
            if !self.target.is_null() {
                (self.gss.release_name)(&mut minor, &mut self.target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Without a ticket the first leg must fail cleanly (→ NTLM fallback), not hang or panic.
    /// Where the library is absent (Linux without Kerberos) `new` already reports Unsupported.
    #[test]
    fn no_ticket_is_an_error() {
        // Point the credential cache at a file that cannot exist, so a developer's real
        // ticket doesn't make the test pass a token instead.
        // SAFETY: only this test touches KRB5CCNAME, and it is read by GSS on this thread.
        unsafe { std::env::set_var("KRB5CCNAME", "FILE:/nonexistent/quena-test-no-ccache") };
        let t0 = Instant::now();
        let r = NegotiateCtx::new("example.com").and_then(|mut c| c.step(None));
        match r {
            Err(AuthError::NoCredentials | AuthError::Unsupported) => {}
            Err(e) => panic!("unexpected error: {e}"),
            // GSS.framework may still find a KCM/keychain identity despite KRB5CCNAME.
            Ok(tok) => assert!(
                cfg!(target_os = "macos") && !tok.is_empty(),
                "no-ticket step produced a token"
            ),
        }
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "no-ticket step took {:?}",
            t0.elapsed()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_library_is_reported() {
        let r = backend::load(&["libquena-does-not-exist.so.9"]);
        assert!(r.is_err());
        assert!(backend::load(&[]).is_err());
    }
}
