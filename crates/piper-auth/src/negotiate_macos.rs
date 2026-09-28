//! Negotiate/Kerberos via GSS.framework (SPNEGO) on macOS. SSO with an existing
//! Kerberos ticket; no ticket → NoCredentials so the caller falls back.

#![allow(non_camel_case_types)]

use crate::AuthError;
use std::ffi::c_void;
use std::os::raw::c_char;

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
const GSS_C_NO_OID: *const GssOidDesc = std::ptr::null();

// SPNEGO mech OID 1.3.6.1.5.5.2
static SPNEGO_OID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
// gss_nt_hostbased_service OID 1.2.840.113554.1.2.1.4
static HOSTBASED_OID: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

const GSS_S_COMPLETE: OM_uint32 = 0;
const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
const GSS_C_MUTUAL_FLAG: OM_uint32 = 2;

#[link(name = "GSS", kind = "framework")]
unsafe extern "C" {
    fn gss_import_name(minor: *mut OM_uint32, input: *const GssBufferDesc, name_type: *const GssOidDesc, output: *mut *mut c_void) -> OM_uint32;
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
    fn gss_delete_sec_context(minor: *mut OM_uint32, ctx: *mut *mut c_void, out: *mut GssBufferDesc) -> OM_uint32;
}

pub struct NegotiateCtx {
    ctx: *mut c_void,
    target: *mut c_void,
    complete: bool,
}

unsafe impl Send for NegotiateCtx {}

impl NegotiateCtx {
    pub fn new(host: &str) -> Result<NegotiateCtx, AuthError> {
        let spn = format!("HTTP@{host}");
        let mut buf = GssBufferDesc { length: spn.len(), value: spn.as_ptr() as *mut c_void };
        let name_oid = GssOidDesc { length: HOSTBASED_OID.len() as u32, elements: HOSTBASED_OID.as_ptr() as *const c_void };
        let mut minor = 0;
        let mut target: *mut c_void = std::ptr::null_mut();
        let major = unsafe { gss_import_name(&mut minor, &mut buf, &name_oid, &mut target) };
        if major != GSS_S_COMPLETE {
            return Err(AuthError::Other(format!("gss_import_name failed (0x{major:x})")));
        }
        Ok(NegotiateCtx { ctx: std::ptr::null_mut(), target, complete: false })
    }

    pub fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        if self.complete {
            return Err(AuthError::Protocol("Negotiate handshake already complete".into()));
        }
        let mech = GssOidDesc { length: SPNEGO_OID.len() as u32, elements: SPNEGO_OID.as_ptr() as *const c_void };
        let in_buf = input.map(|d| GssBufferDesc { length: d.len(), value: d.as_ptr() as *mut c_void });
        let in_ptr = in_buf.as_ref().map(|b| b as *const GssBufferDesc).unwrap_or(std::ptr::null());
        let mut out = GssBufferDesc { length: 0, value: std::ptr::null_mut() };
        let mut minor = 0;
        let mut ret_flags = 0;
        let major = unsafe {
            gss_init_sec_context(
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
            return Err(AuthError::NoCredentials);
        }
        self.complete = major == GSS_S_COMPLETE;
        let token = if out.length > 0 {
            let slice = unsafe { std::slice::from_raw_parts(out.value as *const u8, out.length) }.to_vec();
            unsafe { gss_release_buffer(&mut minor, &mut out) };
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
        let mut out = GssBufferDesc { length: 0, value: std::ptr::null_mut() };
        unsafe {
            if !self.ctx.is_null() {
                gss_delete_sec_context(&mut minor, &mut self.ctx, &mut out);
            }
            if !self.target.is_null() {
                gss_release_name(&mut minor, &mut self.target);
            }
        }
    }
}

// Keep the C types referenced.
const _: () = {
    let _ = GSS_C_NO_OID;
    let _ = SPNEGO_OID.len();
    fn _unused(_: *const c_char) {}
};
