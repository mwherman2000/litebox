//! Network-related functionality

use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

use crate::fd::SocketFd;
use crate::platform;
use crate::platform::Instant;

use bitflags::bitflags;
use smoltcp::socket::{icmp, raw, tcp, udp};

pub mod errors;
mod local_ports;
mod phy;

use errors::{
    AcceptError, BindError, CloseError, ConnectError, ListenError, ReceiveError, SendError,
    SocketError,
};
use local_ports::{LocalPort, LocalPortAllocator};

/// IP address for LiteBox interface
// TODO: Make this configurable
const INTERFACE_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// IP address for the gateway
// TODO: Make this configurable
const GATEWAY_IP_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Maximum number of sockets that can ever be active
const MAX_NUMBER_OF_SOCKETS: usize = 1024;

/// Maximum size of rx/tx buffers for sockets
const SOCKET_BUFFER_SIZE: usize = 65536;

/// Limits maximum number of packets in a buffer
const MAX_PACKET_COUNT: usize = 32;

/// The `Network` provides access to all networking related functionality provided by LiteBox.
///
/// A LiteBox `Network` is parametric in the platform it runs on.
pub struct Network<'platform, Platform: platform::IPInterfaceProvider + platform::TimeProvider> {
    platform: &'platform Platform,
    /// The set of sockets
    socket_set: smoltcp::iface::SocketSet<'static>,
    /// Handles into the `socket_set`; the position/index corresponds to the `raw_fd` of the
    /// `SocketFd` given out from this module.
    // TODO: Maybe a better name for this, and `SocketHandle`?
    handles: Vec<Option<SocketHandle>>,
    /// The actual "physical" device, that connects to the platform
    device: phy::Device<'platform, Platform>,
    /// The smoltcp network interface
    interface: smoltcp::iface::Interface,
    /// Initial instant of creation, used as an arbitrary stop point from when time begins
    zero_time: Platform::Instant,
    /// An allocator for local ports
    // TODO: Maybe we should have separate allocators for TCP, UDP, ...?
    local_port_allocator: LocalPortAllocator,
}

impl<'platform, Platform: platform::IPInterfaceProvider + platform::TimeProvider>
    Network<'platform, Platform>
{
    /// Construct a new `Network` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialization step,
    /// and the created `Network` handle is expected to be shared across all usage over the
    /// system.
    pub fn new(platform: &'platform Platform) -> Self {
        let mut device = phy::Device::new(platform);
        let config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::ZERO);
        interface.update_ip_addrs(|ip_addrs| {
            match ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(INTERFACE_IP_ADDR),
                24,
            )) {
                Ok(()) => {}
                Err(_) => unreachable!(),
            }
        });
        match interface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY_IP_ADDR)
        {
            Ok(None) => {}
            _ => unreachable!(),
        }
        Self {
            platform,
            socket_set: smoltcp::iface::SocketSet::new(vec![]),
            handles: vec![],
            device,
            interface,
            zero_time: platform.now(),
            local_port_allocator: LocalPortAllocator::new(),
        }
    }
}

/// [`SocketHandle`] stores all relevant information for a specific [`SocketFd`], for easy access
/// from [`SocketFd`], _except_ the `Socket` itself which is stored in the [`Sockets::socket_set`].
struct SocketHandle {
    /// The handle into the `socket_set`
    handle: smoltcp::iface::SocketHandle,
    // Protocol-specific data
    specific: ProtocolSpecific,
}

impl core::ops::Deref for SocketHandle {
    type Target = ProtocolSpecific;
    fn deref(&self) -> &Self::Target {
        &self.specific
    }
}
impl core::ops::DerefMut for SocketHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.specific
    }
}

/// The [`ProtocolSpecific`] stores socket-type-specific data
enum ProtocolSpecific {
    Tcp(TcpSpecific),
    Udp(UdpSpecific),
    Icmp(IcmpSpecific),
    Raw(RawSpecific),
}

/// Socket-specific data for TCP sockets
struct TcpSpecific {
    /// A local port associated with this socket, if any
    local_port: Option<LocalPort>,
    /// Server socket specific data
    server_socket: Option<TcpServerSpecific>,
}

/// Socket-specific data for TCP server sockets
struct TcpServerSpecific {
    /// IP listening endpoint, if used as a server socket
    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint,
    /// Specified backlog via `listen`, no packets can be `accept`ed unless this is `Some`
    backlog: Option<u16>,
    /// Handles into the top-level `socket_set` for when things are `accept`ed.
    socket_set_handles: Vec<smoltcp::iface::SocketHandle>,
}

impl TcpServerSpecific {
    fn refill_to_backlog(&mut self, socket_set: &mut smoltcp::iface::SocketSet) {
        let backlog = self.backlog.unwrap();
        for _ in self.socket_set_handles.len()..backlog.into() {
            let mut listening_socket = tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            );
            match listening_socket.listen(self.ip_listen_endpoint) {
                Ok(()) => {}
                Err(tcp::ListenError::InvalidState) => {
                    // Impossible, because we _just_ created a new tcp::Socket, which begins
                    // in CLOSED state.
                    unreachable!()
                }
                Err(tcp::ListenError::Unaddressable) => {
                    // Impossible, since listen endpoint port is non 0.
                    unreachable!()
                }
            };
            self.socket_set_handles
                .push(socket_set.add(listening_socket));
        }
    }
}

/// Socket-specific data for UDP sockets
struct UdpSpecific {}

/// Socket-specific data for ICMP sockets
struct IcmpSpecific {}

/// Socket-specific data for RAW sockets
struct RawSpecific {
    protocol: u8,
}

impl ProtocolSpecific {
    /// Get the [`Protocol`] for this socket
    fn protocol(&self) -> Protocol {
        match self {
            ProtocolSpecific::Tcp(_) => Protocol::Tcp,
            ProtocolSpecific::Udp(_) => Protocol::Udp,
            ProtocolSpecific::Icmp(_) => Protocol::Icmp,
            ProtocolSpecific::Raw(RawSpecific { protocol, .. }) => Protocol::Raw {
                protocol: *protocol,
            },
        }
    }

    /// Obtain a reference to the tcp-socket-specific data. Panics if non-TCP.
    fn tcp(&self) -> &TcpSpecific {
        match self {
            ProtocolSpecific::Tcp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the tcp-socket-specific data. Panics if non-TCP.
    fn tcp_mut(&mut self) -> &mut TcpSpecific {
        match self {
            ProtocolSpecific::Tcp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the udp-socket-specific data. Panics if non-UDP.
    fn udp(&self) -> &UdpSpecific {
        match self {
            ProtocolSpecific::Udp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the udp-socket-specific data. Panics if non-UDP.
    fn udp_mut(&mut self) -> &mut UdpSpecific {
        match self {
            ProtocolSpecific::Udp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the icmp-socket-specific data. Panics if non-ICMP.
    fn icmp(&self) -> &IcmpSpecific {
        match self {
            ProtocolSpecific::Icmp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the icmp-socket-specific data. Panics if non-ICMP.
    fn icmp_mut(&mut self) -> &mut IcmpSpecific {
        match self {
            ProtocolSpecific::Icmp(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a reference to the raw-socket-specific data. Panics if non-RAW.
    fn raw(&self) -> &RawSpecific {
        match self {
            ProtocolSpecific::Raw(specific) => specific,
            _ => unreachable!(),
        }
    }

    /// Obtain a mutable reference to the raw-socket-specific data. Panics if non-RAW.
    fn raw_mut(&mut self) -> &mut RawSpecific {
        match self {
            ProtocolSpecific::Raw(specific) => specific,
            _ => unreachable!(),
        }
    }
}

impl<Platform: platform::IPInterfaceProvider + platform::TimeProvider> Network<'_, Platform> {
    /// Explicitly private-only function that returns the current (smoltcp) Instant, relative to the
    /// initialized arbitrary 0-point in time.
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            // This conversion from u128 to i64 should practically never fail, since 2^63
            // microseconds is roughly 250 years. If a system has been up for that long, then it
            // deserves to panic.
            i64::try_from(
                self.zero_time
                    .duration_since(&self.device.platform.now())
                    .as_micros(),
            )
            .unwrap(),
        )
    }

    /// Creates a socket.
    pub fn socket(&mut self, protocol: Protocol) -> Result<SocketFd, SocketError> {
        let handle = match protocol {
            Protocol::Tcp => self.socket_set.add(tcp::Socket::new(
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
                smoltcp::storage::RingBuffer::new(vec![0u8; SOCKET_BUFFER_SIZE]),
            )),
            Protocol::Udp => self.socket_set.add(udp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Icmp => self.socket_set.add(icmp::Socket::new(
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
                smoltcp::storage::PacketBuffer::new(
                    vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                    vec![0u8; SOCKET_BUFFER_SIZE],
                ),
            )),
            Protocol::Raw { protocol } => {
                // TODO: Should we maintain a specific allow-list of protocols for raw sockets?
                // Should we allow everything except TCP/UDP/ICMP? Should we allow everything? These
                // questions should be resolved; for now I am disallowing everything else.
                return Err(SocketError::UnsupportedProtocol(protocol));

                self.socket_set.add(raw::Socket::new(
                    smoltcp::wire::IpVersion::Ipv4,
                    smoltcp::wire::IpProtocol::from(protocol),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                    smoltcp::storage::PacketBuffer::new(
                        vec![smoltcp::storage::PacketMetadata::EMPTY; MAX_PACKET_COUNT],
                        vec![0u8; SOCKET_BUFFER_SIZE],
                    ),
                ))
            }
        };

        Ok(self.new_socket_fd_for(SocketHandle {
            handle,
            specific: match protocol {
                Protocol::Tcp => ProtocolSpecific::Tcp(TcpSpecific {
                    local_port: None,
                    server_socket: None,
                }),
                Protocol::Udp => unimplemented!(),
                Protocol::Icmp => unimplemented!(),
                Protocol::Raw { protocol } => unimplemented!(),
            },
        }))
    }

    /// Creates a new [`SocketFd`] for a newly-created [`SocketHandle`].
    fn new_socket_fd_for(&mut self, socket_handle: SocketHandle) -> SocketFd {
        // TODO: We can do reuse of fds if we maintained a free-list or similar; for now, we just
        // grab an entirely new fd anytime there is a new socket to be made.

        let raw_fd = self.handles.len();
        self.handles.push(Some(socket_handle));

        SocketFd {
            x: crate::fd::OwnedFd::new(raw_fd),
        }
    }

    /// Close the socket at `fd`
    pub fn close(&mut self, fd: SocketFd) -> Result<(), CloseError> {
        let mut socket_handle =
            core::mem::take(&mut self.handles[fd.x.as_usize()]).ok_or(CloseError::InvalidFd)?;
        let socket = self.socket_set.remove(socket_handle.handle);
        match socket {
            smoltcp::socket::Socket::Raw(_) | smoltcp::socket::Socket::Icmp(_) => {
                // There is no close/abort for raw and icmp sockets
            }
            smoltcp::socket::Socket::Udp(mut socket) => {
                socket.close();
            }
            smoltcp::socket::Socket::Tcp(mut socket) => {
                if let Some(local_port) = socket_handle.specific.tcp_mut().local_port.take() {
                    self.local_port_allocator.deallocate(local_port);
                }
                // TODO: Should we `.close()` or should we `.abort()`?
                socket.abort();
            }
        }
        let SocketFd { x: mut fd } = fd;
        fd.mark_as_closed();
        Ok(())
    }

    /// Initiate a connection to an IP address
    pub fn connect(&mut self, fd: &SocketFd, addr: &SocketAddr) -> Result<(), ConnectError> {
        let SocketAddr::V4(addr) = addr else {
            return Err(ConnectError::UnsupportedAddress(*addr));
        };

        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(ConnectError::InvalidFd)?;

        match socket_handle.protocol() {
            Protocol::Tcp => {
                let socket: &mut tcp::Socket = self.socket_set.get_mut(socket_handle.handle);
                let local_port = self.local_port_allocator.ephemeral_port()?;
                let local_endpoint: smoltcp::wire::IpListenEndpoint = local_port.port().into();
                let addr: smoltcp::wire::IpEndpoint = (*addr).into();
                match socket.connect(self.interface.context(), addr, local_endpoint) {
                    Ok(()) => {}
                    Err(tcp::ConnectError::InvalidState) => unreachable!(),
                    Err(tcp::ConnectError::Unaddressable) => todo!(),
                }
                let old_port =
                    core::mem::replace(&mut socket_handle.tcp_mut().local_port, Some(local_port));
                if old_port.is_some() {
                    // Need to think about how to handle this situation
                    unimplemented!()
                }
                Ok(())
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    /// Bind a socket to a specific address and port.
    pub fn bind(&mut self, fd: &SocketFd, socket_addr: &SocketAddr) -> Result<(), BindError> {
        let SocketAddr::V4(addr) = socket_addr else {
            return Err(BindError::UnsupportedAddress(*socket_addr));
        };

        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(BindError::InvalidFd)?;

        match socket_handle.protocol() {
            Protocol::Tcp => {
                if socket_handle.tcp().server_socket.is_some() {
                    // Need to think about how to handle this situation where this has already been
                    // marked as a server socket.
                    unimplemented!()
                }
                let port = match self.local_port_allocator.specific_port(
                    addr.port()
                        .try_into()
                        .or(Err(BindError::UnsupportedAddress(*socket_addr)))?,
                ) {
                    Ok(lp) => {
                        let old_lp =
                            core::mem::replace(&mut socket_handle.tcp_mut().local_port, Some(lp));
                        if let Some(old) = old_lp {
                            self.local_port_allocator.deallocate(old);
                            // Currently unsure if the dealloc is sufficient and if we need to do
                            // anything else here (possibly return an error message due to trying to
                            // do things to a connected socket, not sure), so just marking as
                            // unimplemented for now to trigger a panic.
                            unimplemented!()
                        }
                        addr.port()
                    }
                    Err(e) => match e {
                        local_ports::LocalPortAllocationError::AlreadyInUse(p) => {
                            return Err(BindError::PortAlreadyInUse(p));
                        }
                        local_ports::LocalPortAllocationError::NoAvailableFreePorts => {
                            unreachable!()
                        }
                    },
                };
                socket_handle.tcp_mut().server_socket = Some(TcpServerSpecific {
                    ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                        addr: Some(smoltcp::wire::IpAddress::Ipv4(*addr.ip())),
                        port,
                    },
                    backlog: None,
                    socket_set_handles: vec![],
                });
                Ok(())
            }
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    /// Prepare a socket to accept incoming connections. Marks the socket as a passive socket, such
    /// that it will be used to accept new connection requests via [`accept`](Self::accept).
    ///
    /// The `backlog` argument defines the maximum length to which the queue of pending connections
    /// the `fd` may grow. This function is allowed to silently cap the value to a reasonable upper
    /// bound.
    pub fn listen(&mut self, fd: &SocketFd, backlog: u16) -> Result<(), ListenError> {
        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(ListenError::InvalidFd)?;

        if backlog == 0 {
            // What should actually happen here?
            unimplemented!()
        }

        // This prevents users from overloading things too badly; 4096 is the upper limit with
        // similar silent-cap behavior since Linux 5.4 (earlier versions capped even smaller, at
        // 128, but we use the larger value to be more flexible).
        //
        // We don't actively depend on this specific value, and it can be changed out at any time
        // without any significant issue.
        let backlog = backlog.min(4096);

        match &mut socket_handle.specific {
            ProtocolSpecific::Tcp(handle) => {
                if handle.server_socket.is_none() {
                    let local_port =
                        self.local_port_allocator
                            .ephemeral_port()
                            .map_err(|e| match e {
                                local_ports::LocalPortAllocationError::AlreadyInUse(_) => {
                                    unreachable!()
                                }
                                local_ports::LocalPortAllocationError::NoAvailableFreePorts => {
                                    ListenError::NoAvailableFreeEphemeralPorts
                                }
                            })?;
                    let port = local_port.port();
                    let old_local_port = handle.local_port.replace(local_port);
                    if let Some(lp) = old_local_port {
                        self.local_port_allocator.deallocate(lp);
                        // Should anything else be done here?
                        unimplemented!()
                    }
                    handle.server_socket = Some(TcpServerSpecific {
                        ip_listen_endpoint: smoltcp::wire::IpListenEndpoint {
                            addr: Some(smoltcp::wire::IpAddress::v4(0, 0, 0, 0)),
                            port,
                        },
                        backlog: None,
                        socket_set_handles: vec![],
                    });
                }
                let Some(server_socket) = &mut handle.server_socket else {
                    unreachable!()
                };
                if server_socket.ip_listen_endpoint.port == 0 {
                    return Err(ListenError::InvalidAddress);
                }
                if server_socket.backlog.is_some() || !server_socket.socket_set_handles.is_empty() {
                    // Need to change the amount of backlog; growing will just work, but truncating
                    // might need some effort to pick which ones to keep/drop
                    unimplemented!()
                } else {
                    server_socket.backlog = Some(backlog);
                    server_socket.socket_set_handles = Vec::with_capacity(backlog.into());
                }
                server_socket.refill_to_backlog(&mut self.socket_set);
                Ok(())
            }
            ProtocolSpecific::Udp(_) => unimplemented!(),
            ProtocolSpecific::Icmp(_) => unimplemented!(),
            ProtocolSpecific::Raw(_) => unimplemented!(),
        }
    }

    /// Accept a new incoming connection on a listening socket.
    pub fn accept(&mut self, fd: &SocketFd) -> Result<SocketFd, AcceptError> {
        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(AcceptError::InvalidFd)?;

        match &mut socket_handle.specific {
            ProtocolSpecific::Tcp(handle) => {
                let Some(server_socket) = &mut handle.server_socket else {
                    return Err(AcceptError::NotListening);
                };
                if server_socket.backlog.is_none() {
                    return Err(AcceptError::NotListening);
                };
                // (Purely an optimization) remove all handles that are closed, by only keeping ones
                // that are not closed
                server_socket.socket_set_handles.retain(|&h| {
                    let socket: &tcp::Socket = self.socket_set.get(h);
                    socket.state() != tcp::State::Closed
                });
                // Find a socket that has progressed further in its TCP state machine, by finding a
                // socket in a may-send-or-recv state
                let Some(position) = server_socket.socket_set_handles.iter().position(|&h| {
                    let socket: &tcp::Socket = self.socket_set.get(h);
                    socket.may_send() || socket.may_recv()
                }) else {
                    return Err(AcceptError::NoConnectionsReady);
                };
                // Pull that position out of the listening handles
                let ready_handle = server_socket.socket_set_handles.swap_remove(position);
                // Refill to the backlog, so that we can have more listening sockets again if needed
                server_socket.refill_to_backlog(&mut self.socket_set);
                // Grab the local port again, so we can put it into the new `TcpSpecific`
                let local_port = handle
                    .local_port
                    .as_ref()
                    .map(|lp| self.local_port_allocator.allocate_same_local_port(lp));
                // Create a new FD to hand it back out to the user
                Ok(self.new_socket_fd_for(SocketHandle {
                    handle: ready_handle,
                    specific: ProtocolSpecific::Tcp(TcpSpecific {
                        local_port,
                        server_socket: None,
                    }),
                }))
            }
            ProtocolSpecific::Udp(_) => unimplemented!(),
            ProtocolSpecific::Icmp(_) => unimplemented!(),
            ProtocolSpecific::Raw(_) => unimplemented!(),
        }
    }

    /// Send data over a connected socket.
    pub fn send(
        &mut self,
        fd: &SocketFd,
        buf: &[u8],
        flags: SendFlags,
    ) -> Result<usize, SendError> {
        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(SendError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol() {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .send_slice(buf)
                .map_err(|tcp::SendError::InvalidState| SendError::SocketInInvalidState),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }

    /// Receive data from a connected socket.
    pub fn receive(
        &mut self,
        fd: &SocketFd,
        buf: &mut [u8],
        flags: ReceiveFlags,
    ) -> Result<usize, ReceiveError> {
        let socket_handle = self.handles[fd.x.as_usize()]
            .as_mut()
            .ok_or(ReceiveError::InvalidFd)?;

        if !flags.is_empty() {
            unimplemented!()
        }

        match socket_handle.protocol() {
            Protocol::Tcp => self
                .socket_set
                .get_mut::<tcp::Socket>(socket_handle.handle)
                .recv_slice(buf)
                .map_err(|e| match e {
                    tcp::RecvError::InvalidState => ReceiveError::OperationFinished,
                    tcp::RecvError::Finished => ReceiveError::SocketInInvalidState,
                }),
            Protocol::Udp => unimplemented!(),
            Protocol::Icmp => unimplemented!(),
            Protocol::Raw { protocol } => unimplemented!(),
        }
    }
}

/// Protocols for sockets supported by LiteBox
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Raw { protocol: u8 },
}

bitflags! {
    /// Flags for the `receive` function.
    pub struct ReceiveFlags: u32 {
        /// `MSG_CMSG_CLOEXEC`: close-on-exec for the associated file descriptor
        const CMSG_CLOEXEC = 0x40000000;
        /// `MSG_DONTWAIT`: non-blocking operation
        const DONTWAIT = 0x40;
        /// `MSG_ERRQUEUE`: destination for error messages
        const ERRQUEUE = 0x2000;
        /// `MSG_OOB`: requests receipt of out-of-band data
        const OOB = 0x1;
        /// `MSG_PEEK`: requests to peek at incoming messages
        const PEEK = 0x2;
        /// `MSG_TRUNC`: truncate the message
        const TRUNC = 0x20;
        /// `MSG_WAITALL`: wait for the full amount of data
        const WAITALL = 0x100;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// Flags for the `send` function.
    pub struct SendFlags: u32 {
        /// `MSG_CONFIRM`: requests confirmation of the message delivery.
        const CONFIRM = 0x800;
        /// `MSG_DONTROUTE`: send the message directly to the interface, bypassing routing.
        const DONTROUTE = 0x4;
        /// `MSG_DONTWAIT`: non-blocking operation, do not wait for buffer space to become available.
        const DONTWAIT = 0x40;
        /// `MSG_EOR`: indicates the end of a record for message-oriented sockets.
        const EOR = 0x80;
        /// `MSG_MORE`: indicates that more data will follow.
        const MORE = 0x8000;
        /// `MSG_NOSIGNAL`: prevents the sending of SIGPIPE signals when writing to a socket that is closed.
        const NOSIGNAL = 0x4000;
        /// `MSG_OOB`: sends out-of-band data.
        const OOB = 0x1;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}
