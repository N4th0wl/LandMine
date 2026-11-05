//! Pengambilan data koneksi jaringan per-PID menggunakan WinAPI GetExtendedTcpTable.
//! Digunakan untuk mendeteksi korelasi jaringan (C2 beaconing atau unduhan payload dari IP publik).

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

#[derive(Debug, Clone)]
pub struct ProcessNetworkInfo {
    pub connections: Vec<SocketAddr>,
    pub has_public_connection: bool,
}

#[cfg(target_os = "windows")]
#[allow(non_snake_case, dead_code)]
mod ffi {
    use std::ffi::c_void;

    pub const AF_INET: u32 = 2;
    pub const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    pub const MIB_TCP_STATE_ESTAB: u32 = 5;

    #[repr(C)]
    pub struct MIB_TCPROW_OWNER_PID {
        pub dwState: u32,
        pub dwLocalAddr: u32,
        pub dwLocalPort: u32,
        pub dwRemoteAddr: u32,
        pub dwRemotePort: u32,
        pub dwOwningPid: u32,
    }

    #[repr(C)]
    pub struct MIB_TCPTABLE_OWNER_PID {
        pub dwNumEntries: u32,
        pub table: [MIB_TCPROW_OWNER_PID; 1],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn GetExtendedTcpTable(
            pTcpTable: *mut c_void,
            pdwSize: *mut u32,
            bOrder: i32,
            ulAf: u32,
            TableClass: u32,
            Reserved: u32,
        ) -> u32;
    }
}

/// Menentukan apakah sebuah IP adalah IP publik (bukan private, loopback, multicast, link-local, dsb).
pub fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 0.0.0.0 / unspecified
    if ip.is_unspecified() {
        return false;
    }
    // 127.0.0.0/8 loopback
    if ip.is_loopback() {
        return false;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return false;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return false;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    // 169.254.0.0/16 Link-local
    if ip.is_link_local() {
        return false;
    }
    // Multicast & Broadcast
    if ip.is_multicast() || ip.is_broadcast() {
        return false;
    }
    true
}

/// Mengambil pemetaan PID -> Koneksi TCP aktif di Windows.
#[cfg(target_os = "windows")]
pub fn get_tcp_connections_by_pid() -> HashMap<u32, ProcessNetworkInfo> {
    let mut map: HashMap<u32, Vec<SocketAddr>> = HashMap::new();
    let mut size: u32 = 0;

    unsafe {
        // Panggilan pertama untuk mendapatkan ukuran buffer
        let _ = ffi::GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            ffi::AF_INET,
            ffi::TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if size == 0 {
            return HashMap::new();
        }

        let mut buf = vec![0u8; size as usize];
        let ret = ffi::GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut size,
            0,
            ffi::AF_INET,
            ffi::TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 {
            return HashMap::new();
        }

        let table = &*(buf.as_ptr() as *const ffi::MIB_TCPTABLE_OWNER_PID);
        let count = table.dwNumEntries as usize;
        let rows_ptr = &table.table[0] as *const ffi::MIB_TCPROW_OWNER_PID;

        for i in 0..count {
            let row = &*rows_ptr.add(i);
            // Saring koneksi yang berstatus ESTABLISHED atau SYN_SENT
            if row.dwRemoteAddr != 0 {
                let ip_bytes = row.dwRemoteAddr.to_ne_bytes();
                let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                // Network byte order (big endian) port
                let port = u16::from_be(row.dwRemotePort as u16);
                let sock = SocketAddr::V4(SocketAddrV4::new(ip, port));
                map.entry(row.dwOwningPid).or_default().push(sock);
            }
        }
    }

    map.into_iter()
        .map(|(pid, conns)| {
            let has_public = conns.iter().any(|addr| match addr {
                SocketAddr::V4(v4) => is_public_ipv4(v4.ip()),
                _ => false,
            });
            (
                pid,
                ProcessNetworkInfo {
                    connections: conns,
                    has_public_connection: has_public,
                },
            )
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn get_tcp_connections_by_pid() -> HashMap<u32, ProcessNetworkInfo> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_private_and_public_ipv4() {
        assert!(!is_public_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_ipv4(&Ipv4Addr::new(10, 0, 1, 5)));
        assert!(!is_public_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_public_ipv4(&Ipv4Addr::new(192, 168, 1, 100)));
        assert!(!is_public_ipv4(&Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_public_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));

        assert!(is_public_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_public_ipv4(&Ipv4Addr::new(142, 250, 190, 46)));
    }
}
