//! Lapisan platform: semua FFI / kode spesifik OS dikumpulkan di sini supaya
//! modul lain tetap bersih dan portable.

pub mod authenticode;
pub mod defense;
pub mod network;
pub mod pe_version;

pub use authenticode::{verify_signature, SignatureStatus};
pub use defense::{
    dump_and_kill_process, is_failsafe_protected, kill_process, suspend_process, DefenseAction,
};
pub use network::{get_tcp_connections_by_pid, is_public_ipv4, ProcessNetworkInfo};

use std::path::PathBuf;

#[cfg(target_os = "windows")]
mod ffi {
    use std::ffi::c_void;

    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ELEVATION_CLASS: u32 = 20;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        pub fn CloseHandle(handle: *mut c_void) -> i32;
        pub fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            buffer: *mut u16,
            size: *mut u32,
        ) -> i32;
        pub fn GetStdHandle(std_handle: u32) -> *mut c_void;
        pub fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> i32;
    }
}

/// Apakah proses ini berjalan dengan hak Administrator (token elevated)?
#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        if ffi::OpenProcessToken(ffi::GetCurrentProcess(), ffi::TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = ffi::GetTokenInformation(
            token,
            ffi::TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        ffi::CloseHandle(token);
        ok != 0 && elevation != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_elevated() -> bool {
    false
}

/// Memeriksa apakah suatu proses target berjalan dengan hak akses elevated.
#[cfg(target_os = "windows")]
pub fn is_process_elevated(pid: u32) -> bool {
    unsafe {
        let handle = ffi::OpenProcess(ffi::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok_token = ffi::OpenProcessToken(handle, ffi::TOKEN_QUERY, &mut token);
        if ok_token == 0 || token.is_null() {
            ffi::CloseHandle(handle);
            return false;
        }
        let mut elevation: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = ffi::GetTokenInformation(
            token,
            ffi::TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        ffi::CloseHandle(token);
        ffi::CloseHandle(handle);
        ok != 0 && elevation != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn is_process_elevated(_pid: u32) -> bool {
    false
}

// Jadi gini Ko, kita pakai ExecutablePath() dari windows API
// Habis itu kita pakai sysinfo::Process::exe() sebagai fallback
// Kenapa? Karena sysinfo::Process::exe() itu kadang error
// Terus kita pakai PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
// Supaya bisa baca process SYSTEM
#[cfg(target_os = "windows")]
pub fn query_image_path(pid: u32) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    unsafe {
        let handle = ffi::OpenProcess(ffi::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = vec![0u16; 4096];
        let mut len = buf.len() as u32;

        let ok = ffi::QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        ffi::CloseHandle(handle);

        if ok == 0 || len == 0 {
            return None;
        }

        Some(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
pub fn query_image_path(_pid: u32) -> Option<PathBuf> {
    None
}

/// Mengaktifkan ANSI escape (warna) di console stdout.
/// Mengembalikan `false` jika stdout bukan terminal (mis. di-redirect ke file/pipe).
#[cfg(target_os = "windows")]
pub fn enable_ansi() -> bool {
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    unsafe {
        let handle = ffi::GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle as isize == -1 {
            return false;
        }
        let mut mode: u32 = 0;
        if ffi::GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        ffi::SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enable_ansi() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}
