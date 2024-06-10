use std::{io, net::SocketAddr, time::Duration};

use mio::net::UdpSocket;

#[cfg(feature = "network_testing")]
use super::network_testing::NetworkTesting;
#[cfg(feature = "network_testing")]
use std::sync::MutexGuard;
#[cfg(feature = "network_testing")]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "network_testing"))]
struct NetworkTesting;

#[cfg(not(feature = "network_testing"))]
impl NetworkTesting {
    pub fn new() -> Self {
        NetworkTesting
    }
}

pub trait NetworkCircumstances: Send {
    /// Whether or not the packet should be dropped before sending.
    /// Does not affect receiving.
    fn simulate_packet_loss(&mut self, packet_size: usize) -> bool;
    /// How much artificial latency to add to the packet (added to the current latency of the connection).
    /// This can also be used to simulate packet reordering when the latency is not constant.
    fn simulate_packet_latency(&mut self, packet_size: usize) -> Duration;
}

#[derive(Clone)]
pub struct PerfectNetworkCircumstances;

impl NetworkCircumstances for PerfectNetworkCircumstances {
    fn simulate_packet_loss(&mut self, _packet_size: usize) -> bool {
        false
    }

    fn simulate_packet_latency(&mut self, _packet_size: usize) -> Duration {
        Duration::ZERO
    }
}

#[cfg(feature = "network_testing")]
pub struct Socket {
    inner: Arc<Mutex<UdpSocket>>,
    connected_addr: Option<SocketAddr>,
    network_testing: NetworkTesting,
}

#[cfg(not(feature = "network_testing"))]
pub struct Socket {
    inner: UdpSocket,
    connected_addr: Option<SocketAddr>,
    network_testing: NetworkTesting,
}

impl Socket {
    pub fn new(
        socket: std::net::UdpSocket,
        network_circumstances: Option<Box<dyn NetworkCircumstances>>,
    ) -> Result<Self, io::Error> {
        socket.set_nonblocking(true)?;
        #[cfg(feature = "network_testing")]
        {
            let socket = Arc::new(Mutex::new(UdpSocket::from_std(socket)));
            Ok(Socket {
                inner: socket.clone(),
                connected_addr: None,
                network_testing: NetworkTesting::new(
                    socket,
                    network_circumstances.unwrap_or_else(|| Box::new(PerfectNetworkCircumstances)),
                ),
            })
        }

        #[cfg(not(feature = "network_testing"))]
        {
            Ok(Socket {
                inner: UdpSocket::from_std(socket),
                connected_addr: None,
                network_testing: NetworkTesting::new(),
            })
        }
    }

    #[cfg(feature = "network_testing")]
    pub fn inner(&self) -> MutexGuard<'_, mio::net::UdpSocket> {
        self.inner.lock().unwrap()
    }

    #[cfg(not(feature = "network_testing"))]
    pub fn inner(&mut self) -> &mut UdpSocket {
        &mut self.inner
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error> {
        self.inner().connect(addr)?;
        self.connected_addr = Some(addr);
        Ok(())
    }

    pub fn send_to(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), io::Error> {
        #[cfg(feature = "network_testing")]
        {
            self.network_testing.send(addr, data.to_vec());
            return Ok(());
        }
        #[cfg(not(feature = "network_testing"))]
        {
            self.inner.send_to(data, addr)?;
            return Ok(());
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), io::Error> {
        if let Some(_addr) = self.connected_addr {
            #[cfg(feature = "network_testing")]
            {
                self.network_testing.send(_addr, data.to_vec());
                return Ok(());
            }
            #[cfg(not(feature = "network_testing"))]
            {
                self.inner.send(data)?;
                return Ok(());
            }
        } else {
            panic!("Not connected to any address");
        }
    }

    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        #[cfg(feature = "network_testing")]
        {
            self.inner.lock().unwrap().recv_from(buf)
        }
        #[cfg(not(feature = "network_testing"))]
        {
            self.inner.recv_from(buf)
        }
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        #[cfg(feature = "network_testing")]
        {
            self.inner.lock().unwrap().recv(buf)
        }
        #[cfg(not(feature = "network_testing"))]
        {
            self.inner.recv(buf)
        }
    }
}
