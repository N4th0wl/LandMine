//! Verifikasi Digital Signature Authenticode menggunakan WinAPI WinVerifyTrust.
//! Memastikan integritas dan keaslian binary Microsoft Windows (mencegah masquerading).

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    UntrustedOrCorrupt,
    Unavailable,
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case, dead_code, clippy::upper_case_acronyms)]
mod ffi {
    use std::ffi::c_void;

    #[repr(C)]
    pub struct GUID {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }

    pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    pub const WTD_UI_NONE: u32 = 2;
    pub const WTD_REVOKE_NONE: u32 = 0;
    pub const WTD_CHOICE_FILE: u32 = 1;
    pub const WTD_STATEACTION_IGNORE: u32 = 0;
    pub const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x00001000;

    #[repr(C)]
    pub struct WINTRUST_FILE_INFO {
        pub cbStruct: u32,
        pub pcwszFilePath: *const u16,
        pub hFile: *mut c_void,
        pub pgKnownSubject: *const GUID,
    }

    #[repr(C)]
    pub struct WINTRUST_DATA {
        pub cbStruct: u32,
        pub pPolicyCallbackData: *mut c_void,
        pub pSIPClientData: *mut c_void,
        pub dwUIChoice: u32,
        pub fdwRevocationChecks: u32,
        pub dwUnionChoice: u32,
        pub pFile: *mut WINTRUST_FILE_INFO,
        pub dwStateAction: u32,
        pub hWVTStateData: *mut c_void,
        pub pwszURLReference: *mut u16,
        pub dwProvFlags: u32,
        pub dwUIContext: u32,
        pub pSignatureSettings: *mut c_void,
    }

    #[link(name = "wintrust")]
    extern "system" {
        pub fn WinVerifyTrust(
            hwnd: *mut c_void,
            pgActionID: *const GUID,
            pWVTData: *mut c_void,
        ) -> i32;
    }
}

/// Memverifikasi digital signature sebuah file executable di Windows.
#[cfg(target_os = "windows")]
pub fn verify_signature<P: AsRef<Path>>(path: P) -> SignatureStatus {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let path_ref = path.as_ref();
    if !path_ref.exists() {
        return SignatureStatus::Unavailable;
    }

    let wide_path: Vec<u16> = OsStr::new(path_ref.as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = ffi::WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<ffi::WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null(),
    };

    let mut trust_data = ffi::WINTRUST_DATA {
        cbStruct: std::mem::size_of::<ffi::WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: ffi::WTD_UI_NONE,
        fdwRevocationChecks: ffi::WTD_REVOKE_NONE,
        dwUnionChoice: ffi::WTD_CHOICE_FILE,
        pFile: &mut file_info,
        dwStateAction: ffi::WTD_STATEACTION_IGNORE,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: ffi::WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let status = unsafe {
        ffi::WinVerifyTrust(
            std::ptr::null_mut(),
            &ffi::WINTRUST_ACTION_GENERIC_VERIFY_V2,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        )
    };

    let status_u32 = status as u32;

    match status_u32 {
        0 => SignatureStatus::Valid,
        0x800B0100 => SignatureStatus::Unsigned, // TRUST_E_NOSIGNATURE
        _ => SignatureStatus::UntrustedOrCorrupt,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn verify_signature<P: AsRef<Path>>(_path: P) -> SignatureStatus {
    SignatureStatus::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_existent_file_is_unavailable() {
        assert_eq!(
            verify_signature("C:\\non_existent_path_12345.exe"),
            SignatureStatus::Unavailable
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_system_binary_is_validly_signed() {
        let explorer = std::path::Path::new("C:\\Windows\\explorer.exe");
        if explorer.exists() {
            let res = verify_signature(explorer);
            assert_eq!(
                res,
                SignatureStatus::Valid,
                "explorer.exe should have a valid signature"
            );
        }
    }
}
