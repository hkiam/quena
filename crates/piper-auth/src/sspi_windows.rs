//! Windows SSPI: NTLM and Negotiate (Kerberos) with SSO for the logged-in user,
//! or explicit credentials via SEC_WINNT_AUTH_IDENTITY. Self-contained FFI
//! against secur32.dll (like the macOS GSS binding), no extra windows-sys deps.

#![allow(non_snake_case, non_camel_case_types)]

use crate::AuthError;
use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct SecHandle {
    dwLower: usize,
    dwUpper: usize,
}
impl SecHandle {
    fn zero() -> Self {
        SecHandle { dwLower: 0, dwUpper: 0 }
    }
    fn is_set(&self) -> bool {
        self.dwLower != 0 || self.dwUpper != 0
    }
}

#[repr(C)]
struct SecBuffer {
    cbBuffer: u32,
    BufferType: u32,
    pvBuffer: *mut c_void,
}

#[repr(C)]
struct SecBufferDesc {
    ulVersion: u32,
    cBuffers: u32,
    pBuffers: *mut SecBuffer,
}

#[repr(C)]
struct SecWinntAuthIdentityW {
    User: *const u16,
    UserLength: u32,
    Domain: *const u16,
    DomainLength: u32,
    Password: *const u16,
    PasswordLength: u32,
    Flags: u32,
}

const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_VERSION: u32 = 0;
const SECPKG_CRED_OUTBOUND: u32 = 2;
const SECURITY_NATIVE_DREP: u32 = 0x10;
const ISC_REQ_CONNECTION: u32 = 0x800;
const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x100;
const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 2;

const SEC_E_OK: i32 = 0;
const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312u32 as i32;
const SEC_I_COMPLETE_NEEDED: i32 = 0x0009_0313u32 as i32;
const SEC_I_COMPLETE_AND_CONTINUE: i32 = 0x0009_0314u32 as i32;

#[link(name = "secur32")]
unsafe extern "system" {
    fn AcquireCredentialsHandleW(
        principal: *const u16,
        package: *const u16,
        cred_use: u32,
        logon_id: *const c_void,
        auth_data: *const c_void,
        get_key_fn: *const c_void,
        get_key_arg: *const c_void,
        cred: *mut SecHandle,
        expiry: *mut i64,
    ) -> i32;
    fn InitializeSecurityContextW(
        cred: *const SecHandle,
        ctx: *const SecHandle,
        target: *const u16,
        flags: u32,
        reserved1: u32,
        data_rep: u32,
        input: *const SecBufferDesc,
        reserved2: u32,
        new_ctx: *mut SecHandle,
        output: *mut SecBufferDesc,
        attrs: *mut u32,
        expiry: *mut i64,
    ) -> i32;
    fn DeleteSecurityContext(ctx: *const SecHandle) -> i32;
    fn FreeCredentialsHandle(cred: *const SecHandle) -> i32;
    fn FreeContextBuffer(buf: *mut c_void) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub struct SspiCtx {
    cred: SecHandle,
    ctx: SecHandle,
    target: Vec<u16>,
    have_ctx: bool,
    complete: bool,
    // Keep identity buffers alive for the duration.
    _user: Vec<u16>,
    _domain: Vec<u16>,
    _password: Vec<u16>,
}

unsafe impl Send for SspiCtx {}

impl SspiCtx {
    /// `package` = "Negotiate" or "NTLM". Empty user → SSO with the logged-in user.
    pub fn new(package: &str, host: &str, user: &str, domain: &str, password: &str) -> Result<SspiCtx, AuthError> {
        let pkg = wide(package);
        let target = wide(&format!("HTTP/{host}"));
        let mut cred = SecHandle::zero();
        let mut expiry = 0i64;

        let user_w = wide(user);
        let domain_w = wide(domain);
        let pass_w = wide(password);
        let use_explicit = !user.is_empty();
        let identity = SecWinntAuthIdentityW {
            User: user_w.as_ptr(),
            UserLength: user.encode_utf16().count() as u32,
            Domain: domain_w.as_ptr(),
            DomainLength: domain.encode_utf16().count() as u32,
            Password: pass_w.as_ptr(),
            PasswordLength: password.encode_utf16().count() as u32,
            Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        };
        let auth_ptr = if use_explicit { &identity as *const _ as *const c_void } else { std::ptr::null() };
        let status = unsafe {
            AcquireCredentialsHandleW(std::ptr::null(), pkg.as_ptr(), SECPKG_CRED_OUTBOUND, std::ptr::null(), auth_ptr, std::ptr::null(), std::ptr::null(), &mut cred, &mut expiry)
        };
        if status != SEC_E_OK {
            return Err(AuthError::Other(format!("AcquireCredentialsHandle({package}) failed: 0x{status:08x}")));
        }
        Ok(SspiCtx {
            cred,
            ctx: SecHandle::zero(),
            target,
            have_ctx: false,
            complete: false,
            _user: user_w,
            _domain: domain_w,
            _password: pass_w,
        })
    }

    pub fn step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, AuthError> {
        if self.complete {
            return Err(AuthError::Protocol("SSPI handshake already complete".into()));
        }
        let mut in_buf = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() };
        if let Some(d) = input {
            in_buf.cbBuffer = d.len() as u32;
            in_buf.pvBuffer = d.as_ptr() as *mut c_void;
        }
        let mut in_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut in_buf };
        let mut out_buf = SecBuffer { cbBuffer: 0, BufferType: SECBUFFER_TOKEN, pvBuffer: std::ptr::null_mut() };
        let mut out_desc = SecBufferDesc { ulVersion: SECBUFFER_VERSION, cBuffers: 1, pBuffers: &mut out_buf };
        let mut attrs = 0u32;
        let mut expiry = 0i64;
        let mut new_ctx = SecHandle::zero();
        let status = unsafe {
            InitializeSecurityContextW(
                &self.cred,
                if self.have_ctx { &self.ctx } else { std::ptr::null() },
                self.target.as_ptr(),
                ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NATIVE_DREP,
                if input.is_some() { &in_desc } else { std::ptr::null() },
                0,
                &mut new_ctx,
                &mut out_desc,
                &mut attrs,
                &mut expiry,
            )
        };
        let _ = &mut in_desc;
        if new_ctx.is_set() {
            self.ctx = new_ctx;
            self.have_ctx = true;
        }
        match status {
            SEC_E_OK => self.complete = true,
            SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {}
            other => return Err(AuthError::Other(format!("InitializeSecurityContext failed: 0x{other:08x}"))),
        }
        let token = if out_buf.cbBuffer > 0 && !out_buf.pvBuffer.is_null() {
            let slice = unsafe { std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize) }.to_vec();
            unsafe { FreeContextBuffer(out_buf.pvBuffer) };
            slice
        } else {
            Vec::new()
        };
        Ok(token)
    }
}

impl Drop for SspiCtx {
    fn drop(&mut self) {
        unsafe {
            if self.have_ctx {
                DeleteSecurityContext(&self.ctx);
            }
            if self.cred.is_set() {
                FreeCredentialsHandle(&self.cred);
            }
        }
    }
}
