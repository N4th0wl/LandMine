//! Active Defense & Response (Mitigasi Otomatis & DFIR Forensik):
//! - Process Suspension (NtSuspendProcess)
//! - Process Termination (TerminateProcess)
//! - Quarantine Memory Dump (MiniDumpWriteDump dari dbghelp.dll)
//!
//! Dilengkapi failsafe guard agar tidak menyentuh proses kritis OS atau LandMine sendiri.

use anyhow::{bail, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseAction {
    Suspended,
    Terminated,
    DumpedAndTerminated,
    SkippedFailsafe,
}

const CRITICAL_SYSTEM_NAMES: &[&str] = &[
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "system",
    "registry",
    "winlogon.exe",
];

/// Memeriksa apakah PID atau nama proses termasuk dalam daftar failsafe.
pub fn is_failsafe_protected(pid: u32, name: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let name_lc = name.to_lowercase();
    CRITICAL_SYSTEM_NAMES.contains(&name_lc.as_str())
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case, dead_code, non_upper_case_globals)]
mod ffi {
    use std::ffi::c_void;

    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
    pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
    pub const MiniDumpNormal: u32 = 0x00000000;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut c_void;
        pub fn TerminateProcess(hProcess: *mut c_void, uExitCode: u32) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtSuspendProcess(ProcessHandle: *mut c_void) -> i32;
        pub fn NtResumeProcess(ProcessHandle: *mut c_void) -> i32;
    }

    #[link(name = "dbghelp")]
    extern "system" {
        pub fn MiniDumpWriteDump(
            hProcess: *mut c_void,
            ProcessId: u32,
            hFile: *mut c_void,
            DumpType: u32,
            ExceptionParam: *mut c_void,
            UserStreamParam: *mut c_void,
            CallbackParam: *mut c_void,
        ) -> i32;
    }
}

/// Menangguhkan (suspend/pause) eksekusi proses mencurigakan.
#[cfg(target_os = "windows")]
pub fn suspend_process(pid: u32, name: &str) -> Result<DefenseAction> {
    if is_failsafe_protected(pid, name) {
        return Ok(DefenseAction::SkippedFailsafe);
    }

    unsafe {
        let handle = ffi::OpenProcess(ffi::PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            bail!("cannot open process {} ({}) for suspension", pid, name);
        }
        let status = ffi::NtSuspendProcess(handle);
        ffi::CloseHandle(handle);
        if status != 0 {
            bail!("NtSuspendProcess failed with status {:#x}", status);
        }
    }
    Ok(DefenseAction::Suspended)
}

#[cfg(not(target_os = "windows"))]
pub fn suspend_process(_pid: u32, _name: &str) -> Result<DefenseAction> {
    Ok(DefenseAction::SkippedFailsafe)
}

/// Menghentikan (kill) proses yang terindikasi sangat berbahaya.
#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32, name: &str) -> Result<DefenseAction> {
    if is_failsafe_protected(pid, name) {
        return Ok(DefenseAction::SkippedFailsafe);
    }

    unsafe {
        let handle = ffi::OpenProcess(ffi::PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            bail!("cannot open process {} ({}) for termination", pid, name);
        }
        let ok = ffi::TerminateProcess(handle, 1);
        ffi::CloseHandle(handle);
        if ok == 0 {
            bail!("TerminateProcess failed for PID {}", pid);
        }
    }
    Ok(DefenseAction::Terminated)
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(_pid: u32, _name: &str) -> Result<DefenseAction> {
    Ok(DefenseAction::SkippedFailsafe)
}

/// Menghasilkan memory mini-dump dari proses sebelum proses dimatikan (DFIR forensik).
#[cfg(target_os = "windows")]
pub fn dump_and_kill_process<P: AsRef<Path>>(
    pid: u32,
    name: &str,
    dump_dir: P,
) -> Result<DefenseAction> {
    use std::os::windows::io::AsRawHandle;

    if is_failsafe_protected(pid, name) {
        return Ok(DefenseAction::SkippedFailsafe);
    }

    let dump_dir_ref = dump_dir.as_ref();
    std::fs::create_dir_all(dump_dir_ref)?;

    let dump_filename = format!(
        "quarantine_{}_{}_{}.dmp",
        name,
        pid,
        chrono::Utc::now().timestamp()
    );
    let dump_path = dump_dir_ref.join(dump_filename);

    let file = std::fs::File::create(&dump_path)
        .with_context(|| format!("failed to create dump file {}", dump_path.display()))?;

    unsafe {
        let handle = ffi::OpenProcess(ffi::PROCESS_ALL_ACCESS, 0, pid);
        if !handle.is_null() {
            let _ = ffi::MiniDumpWriteDump(
                handle,
                pid,
                file.as_raw_handle(),
                ffi::MiniDumpNormal,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            let _ = ffi::TerminateProcess(handle, 1);
            ffi::CloseHandle(handle);
        } else {
            // Fallback: coba kill saja jika OpenProcess ALL_ACCESS ditolak
            let _ = kill_process(pid, name);
        }
    }

    Ok(DefenseAction::DumpedAndTerminated)
}

#[cfg(not(target_os = "windows"))]
pub fn dump_and_kill_process<P: AsRef<Path>>(
    _pid: u32,
    _name: &str,
    _dump_dir: P,
) -> Result<DefenseAction> {
    Ok(DefenseAction::SkippedFailsafe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failsafe_protects_critical_processes() {
        assert!(is_failsafe_protected(4, "System"));
        assert!(is_failsafe_protected(100, "svchost.exe"));
        assert!(is_failsafe_protected(200, "lsass.exe"));
        assert!(is_failsafe_protected(std::process::id(), "landmine.exe"));
        assert!(!is_failsafe_protected(12345, "evil_dropper.exe"));
    }
}
