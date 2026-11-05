//! Windows Event Log Provider (Roadmap 3.3).
//! Menulis event deteksi langsung ke Windows Event Log (Application Log)
//! agar dapat dikonsumsi oleh agent SIEM/EDR (Splunk, Wazuh, Elastic Agent, Microsoft Sentinel).

use crate::models::{ProcEvent, Severity};

pub struct WinEventLogger {
    #[cfg(target_os = "windows")]
    handle: *mut std::ffi::c_void,
}

// Safety: event log handle kernel Windows aman dikirim antar thread
unsafe impl Send for WinEventLogger {}
unsafe impl Sync for WinEventLogger {}

#[cfg(target_os = "windows")]
#[allow(non_snake_case, dead_code)]
mod ffi {
    use std::ffi::c_void;

    pub const EVENTLOG_SUCCESS: u16 = 0x0000;
    pub const EVENTLOG_ERROR_TYPE: u16 = 0x0001;
    pub const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
    pub const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;

    #[link(name = "advapi32")]
    extern "system" {
        pub fn RegisterEventSourceW(
            lpUNCServerName: *const u16,
            lpSourceName: *const u16,
        ) -> *mut c_void;
        pub fn DeregisterEventSource(hEventLog: *mut c_void) -> i32;
        pub fn ReportEventW(
            hEventLog: *mut c_void,
            wType: u16,
            wCategory: u16,
            dwEventID: u32,
            lpUserSid: *mut c_void,
            wNumStrings: u16,
            dwDataSize: u32,
            lpStrings: *const *const u16,
            lpRawData: *mut c_void,
        ) -> i32;
    }
}

impl WinEventLogger {
    pub fn new(source_name: &str) -> Self {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            let wide_name: Vec<u16> = OsStr::new(source_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe { ffi::RegisterEventSourceW(std::ptr::null(), wide_name.as_ptr()) };
            Self { handle }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = source_name;
            Self {}
        }
    }

    pub fn report(&self, evt: &ProcEvent) {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;

            if self.handle.is_null() {
                return;
            }

            let log_type = match evt.severity {
                Severity::Critical => ffi::EVENTLOG_ERROR_TYPE,
                Severity::High | Severity::Medium => ffi::EVENTLOG_WARNING_TYPE,
                Severity::Low => ffi::EVENTLOG_INFORMATION_TYPE,
            };

            let json_str = match serde_json::to_string(evt) {
                Ok(s) => s,
                Err(_) => return,
            };

            let wide_msg: Vec<u16> = OsStr::new(&json_str)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let strings_ptr = [wide_msg.as_ptr()];

            unsafe {
                ffi::ReportEventW(
                    self.handle,
                    log_type,
                    0,
                    1001, // Event ID LandMine
                    std::ptr::null_mut(),
                    1,
                    0,
                    strings_ptr.as_ptr(),
                    std::ptr::null_mut(),
                );
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = evt;
        }
    }
}

impl Drop for WinEventLogger {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if !self.handle.is_null() {
                unsafe {
                    ffi::DeregisterEventSource(self.handle);
                }
            }
        }
    }
}
