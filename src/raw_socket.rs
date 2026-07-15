//! Privilege-gated raw Ethernet I/O.
//!
//! Linux uses `AF_PACKET`; other platforms return an explicit unsupported
//! error. Merely importing or constructing codec values never opens a socket.

use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RawSocketConfig {
    pub interface: String,
    pub snaplen: usize,
    pub receive_outgoing: bool,
    pub promiscuous: bool,
    /// Explicit acknowledgement that the host TCP stack may emit competing
    /// RST/ACK packets for crafted TCP flows.
    pub allow_host_tcp: bool,
    /// Drop the entire process to `(uid, gid)` immediately after the raw
    /// socket is opened and configured, before any worker thread is started.
    pub drop_privileges: Option<(u32, u32)>,
}

impl RawSocketConfig {
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            interface: interface.into(),
            snaplen: 65_535,
            receive_outgoing: false,
            promiscuous: false,
            allow_host_tcp: false,
            drop_privileges: None,
        }
    }

    fn validate(&self) -> Result<(), RawSocketError> {
        if self.interface.is_empty() || self.interface.as_bytes().contains(&0) {
            return Err(RawSocketError::configuration(
                "raw interface must be a non-empty name without NUL bytes",
            ));
        }
        if !(64..=1_048_576).contains(&self.snaplen) {
            return Err(RawSocketError::configuration(
                "raw snaplen must be between 64 and 1048576 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSocketErrorKind {
    Unsupported,
    Permission,
    Configuration,
    Io,
}

#[derive(Debug)]
pub struct RawSocketError {
    pub kind: RawSocketErrorKind,
    pub message: String,
}

impl RawSocketError {
    #[cfg(not(target_os = "linux"))]
    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            kind: RawSocketErrorKind::Unsupported,
            message: message.into(),
        }
    }

    fn configuration(message: impl Into<String>) -> Self {
        Self {
            kind: RawSocketErrorKind::Configuration,
            message: message.into(),
        }
    }

    #[cfg(target_os = "linux")]
    fn from_io(context: &str, error: std::io::Error) -> Self {
        let permission = matches!(error.kind(), std::io::ErrorKind::PermissionDenied)
            || matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES));
        if permission {
            Self {
                kind: RawSocketErrorKind::Permission,
                message: format!("{context}: {error}; raw mode requires root or CAP_NET_RAW"),
            }
        } else {
            Self {
                kind: RawSocketErrorKind::Io,
                message: format!("{context}: {error}"),
            }
        }
    }
}

impl fmt::Display for RawSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RawSocketError {}

#[derive(Debug)]
pub struct RawPacketSocket {
    #[cfg(target_os = "linux")]
    fd: std::os::fd::RawFd,
    #[cfg(target_os = "linux")]
    interface_index: i32,
    config: RawSocketConfig,
}

impl RawPacketSocket {
    pub fn open(config: RawSocketConfig) -> Result<Self, RawSocketError> {
        config.validate()?;
        let drop_privileges = config.drop_privileges;
        let socket = open_platform(config)?;
        if let Some((uid, gid)) = drop_privileges {
            drop_platform_privileges(uid, gid)?;
        }
        Ok(socket)
    }

    pub fn send(&self, frame: &[u8]) -> Result<usize, RawSocketError> {
        if frame.len() < 14 {
            return Err(RawSocketError::configuration(
                "raw Ethernet frame must contain at least 14 bytes",
            ));
        }
        send_platform(self, frame)
    }

    /// Receive one frame, returning `None` when the timeout expires.
    pub fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, RawSocketError> {
        receive_platform(self, timeout)
    }

    pub fn interface(&self) -> &str {
        &self.config.interface
    }
}

#[cfg(target_os = "linux")]
fn drop_platform_privileges(uid: u32, gid: u32) -> Result<(), RawSocketError> {
    // Supplementary groups must be cleared before losing CAP_SETGID. Passing
    // a null pointer is valid when the group count is zero.
    // SAFETY: the libc calls take scalar IDs; setgroups receives no array.
    let groups_status = unsafe { libc::setgroups(0, std::ptr::null()) };
    if groups_status != 0 {
        return Err(RawSocketError::from_io(
            "cannot clear supplementary groups after opening raw socket",
            std::io::Error::last_os_error(),
        ));
    }
    // GID must be dropped before UID, since the UID transition clears the
    // remaining effective capabilities.
    // SAFETY: gid is supplied by an explicit CLI option and converted without
    // truncation on Linux, where gid_t and uid_t are u32.
    if unsafe { libc::setgid(gid as libc::gid_t) } != 0 {
        return Err(RawSocketError::from_io(
            "cannot drop GID after opening raw socket",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: see the setgid rationale above.
    if unsafe { libc::setuid(uid as libc::uid_t) } != 0 {
        return Err(RawSocketError::from_io(
            "cannot drop UID after opening raw socket",
            std::io::Error::last_os_error(),
        ));
    }
    // Verify the irreversible transition instead of trusting a successful
    // syscall alone.
    // SAFETY: getuid/geteuid/getgid/getegid take no pointers or arguments.
    let dropped = unsafe {
        libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
    };
    if !dropped {
        return Err(RawSocketError::configuration(
            "raw socket opened but process credential drop did not take effect",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_platform_privileges(_uid: u32, _gid: u32) -> Result<(), RawSocketError> {
    Err(RawSocketError::unsupported(
        "post-open privilege dropping currently requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn open_platform(config: RawSocketConfig) -> Result<RawPacketSocket, RawSocketError> {
    use std::ffi::CString;

    let name = CString::new(config.interface.as_str())
        .map_err(|_| RawSocketError::configuration("interface contains a NUL byte"))?;
    // SAFETY: `name` is a valid NUL-terminated string for this call.
    let interface_index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if interface_index == 0 {
        return Err(RawSocketError::from_io(
            "cannot resolve raw interface",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: arguments are constants accepted by Linux `socket(2)`.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(u16::to_be(libc::ETH_P_ALL as u16)),
        )
    };
    if fd < 0 {
        return Err(RawSocketError::from_io(
            "cannot open AF_PACKET socket",
            std::io::Error::last_os_error(),
        ));
    }
    let result = configure_linux_socket(fd, interface_index as i32, &config);
    if let Err(error) = result {
        // SAFETY: `fd` was returned by `socket` and is owned here.
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(RawPacketSocket {
        fd,
        interface_index: interface_index as i32,
        config,
    })
}

#[cfg(target_os = "linux")]
fn configure_linux_socket(
    fd: std::os::fd::RawFd,
    interface_index: i32,
    config: &RawSocketConfig,
) -> Result<(), RawSocketError> {
    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: u16::to_be(libc::ETH_P_ALL as u16),
        sll_ifindex: interface_index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    // SAFETY: pointer/length refer to the initialized `sockaddr_ll` above.
    let status = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if status < 0 {
        return Err(RawSocketError::from_io(
            "cannot bind AF_PACKET socket",
            std::io::Error::last_os_error(),
        ));
    }
    if !config.receive_outgoing {
        let enabled: libc::c_int = 1;
        // Linux 4.20+ can suppress outgoing packet copies. Failure is benign;
        // `receive_platform` also checks `sll_pkttype` as a portable fallback.
        // SAFETY: value pointer and size match `c_int`.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            );
        }
    }
    if config.promiscuous {
        let request = libc::packet_mreq {
            mr_ifindex: interface_index,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        // SAFETY: request pointer/size match Linux `packet_mreq`.
        let status = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&request as *const libc::packet_mreq).cast(),
                std::mem::size_of_val(&request) as libc::socklen_t,
            )
        };
        if status < 0 {
            return Err(RawSocketError::from_io(
                "cannot enable promiscuous mode",
                std::io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_platform(socket: &RawPacketSocket, frame: &[u8]) -> Result<usize, RawSocketError> {
    let mut address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: u16::to_be(u16::from_be_bytes([frame[12], frame[13]])),
        sll_ifindex: socket.interface_index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };
    address.sll_addr[..6].copy_from_slice(&frame[..6]);
    // SAFETY: frame and address pointers remain valid for the duration of the call.
    let written = unsafe {
        libc::sendto(
            socket.fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if written < 0 {
        Err(RawSocketError::from_io(
            "raw frame send failed",
            std::io::Error::last_os_error(),
        ))
    } else {
        Ok(written as usize)
    }
}

#[cfg(target_os = "linux")]
fn receive_platform(
    socket: &RawPacketSocket,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, RawSocketError> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    loop {
        let mut descriptor = libc::pollfd {
            fd: socket.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready == 0 {
            return Ok(None);
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(RawSocketError::from_io("raw receive poll failed", error));
        }
        let mut frame = vec![0; socket.config.snaplen];
        // SAFETY: address and frame buffers are initialized and lengths are correct.
        let (length, address) = unsafe {
            let mut address: libc::sockaddr_ll = std::mem::zeroed();
            let mut address_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let length = libc::recvfrom(
                socket.fd,
                frame.as_mut_ptr().cast(),
                frame.len(),
                0,
                (&mut address as *mut libc::sockaddr_ll).cast(),
                &mut address_len,
            );
            (length, address)
        };
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(RawSocketError::from_io("raw receive failed", error));
        }
        if !socket.config.receive_outgoing && address.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        frame.truncate(length as usize);
        return Ok(Some(frame));
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        // SAFETY: this instance uniquely owns `fd` until drop.
        unsafe { libc::close(self.fd) };
    }
}

// AF_PACKET has no cross-platform equivalent with compatible semantics.
#[cfg(not(target_os = "linux"))]
fn open_platform(_config: RawSocketConfig) -> Result<RawPacketSocket, RawSocketError> {
    Err(RawSocketError::unsupported(
        "raw packet mode currently requires Linux AF_PACKET",
    ))
}

#[cfg(not(target_os = "linux"))]
fn send_platform(_socket: &RawPacketSocket, _frame: &[u8]) -> Result<usize, RawSocketError> {
    Err(RawSocketError::unsupported(
        "raw packet mode currently requires Linux AF_PACKET",
    ))
}

#[cfg(not(target_os = "linux"))]
fn receive_platform(
    _socket: &RawPacketSocket,
    _timeout: Duration,
) -> Result<Option<Vec<u8>>, RawSocketError> {
    Err(RawSocketError::unsupported(
        "raw packet mode currently requires Linux AF_PACKET",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_checked_before_privileged_io() {
        let mut config = RawSocketConfig::new("");
        assert_eq!(
            RawPacketSocket::open(config.clone()).unwrap_err().kind,
            RawSocketErrorKind::Configuration
        );
        config.interface = "lo".to_string();
        config.snaplen = 1;
        assert_eq!(
            RawPacketSocket::open(config).unwrap_err().kind,
            RawSocketErrorKind::Configuration
        );
    }
}
