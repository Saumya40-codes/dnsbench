use std::{
    io::{self, ErrorKind, Read, Write},
    sync::Arc,
};

use tokio::{
    io::{Interest, Ready},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, pki_types::ServerName},
};

use crate::config::{RunConfig, Transport};

pub(crate) enum Socket {
    Udp(UdpSocket),
    Dot(Box<TlsSocket>),
}

impl Socket {
    pub(crate) async fn connect_tls(config: &RunConfig) -> io::Result<Self> {
        let Transport::Dot { server_name } = config.transport() else {
            unreachable!("TLS connection requires DoT configuration")
        };
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self::connect_with_config(config, Arc::new(tls), server_name.clone()).await
    }

    pub(crate) async fn connect_with_config(
        config: &RunConfig,
        tls: Arc<rustls::ClientConfig>,
        name: String,
    ) -> io::Result<Self> {
        let name = ServerName::try_from(name).map_err(io::Error::other)?;
        let connect = async {
            let tcp = TcpStream::connect(config.server()).await?;
            tcp.set_nodelay(true)?;
            let stream = TlsConnector::from(Arc::clone(&tls))
                .connect(name, tcp)
                .await?;
            let (tcp, mut session) = stream.into_inner();
            // Only one small DNS frame is queued at a time, so writes can be accepted atomically.
            session.set_buffer_limit(None);
            Ok(Self::Dot(Box::new(TlsSocket {
                tcp,
                session,
                tls_config: tls,
                prefix: [0; 2],
                prefix_len: 0,
                body_len: 0,
                received: 0,
                frame: Vec::with_capacity(273),
            })))
        };
        tokio::time::timeout(config.timeout(), connect)
            .await
            .map_err(|_| {
                io::Error::new(ErrorKind::TimedOut, "TCP/TLS connection setup timed out")
            })?
    }

    pub(crate) async fn reconnect_tls(&self, config: &RunConfig) -> io::Result<Self> {
        let (Self::Dot(socket), Transport::Dot { server_name }) = (self, config.transport()) else {
            unreachable!("TLS reconnection requires a DoT socket")
        };
        Self::connect_with_config(config, Arc::clone(&socket.tls_config), server_name.clone()).await
    }

    pub(crate) fn try_send(&mut self, packet: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.try_send(packet),
            Self::Dot(socket) => {
                socket.flush()?;
                if socket.session.wants_write() {
                    return Err(ErrorKind::WouldBlock.into());
                }
                socket.frame.clear();
                let length = u16::try_from(packet.len()).map_err(|_| {
                    io::Error::new(ErrorKind::InvalidInput, "DNS frame exceeds 65535 bytes")
                })?;
                socket.frame.extend_from_slice(&length.to_be_bytes());
                socket.frame.extend_from_slice(packet);
                socket.session.writer().write_all(&socket.frame)?;
                // Flushing is driven by receive/readiness so an accepted frame is always tracked.
                Ok(packet.len())
            }
        }
    }

    pub(crate) fn try_recv(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.try_recv(packet),
            Self::Dot(socket) => socket.receive(packet),
        }
    }

    pub(crate) async fn ready(&self, interest: Interest) -> io::Result<Ready> {
        match self {
            Self::Udp(socket) => socket.ready(interest).await,
            Self::Dot(socket) => {
                socket
                    .tcp
                    .ready(if socket.session.wants_write() {
                        interest | Interest::WRITABLE
                    } else {
                        interest
                    })
                    .await
            }
        }
    }
}

pub(crate) struct TlsSocket {
    tcp: TcpStream,
    session: rustls::ClientConnection,
    tls_config: Arc<rustls::ClientConfig>,
    prefix: [u8; 2],
    prefix_len: usize,
    body_len: usize,
    received: usize,
    frame: Vec<u8>,
}

impl TlsSocket {
    fn flush(&mut self) -> io::Result<()> {
        while self.session.wants_write() {
            match self.session.write_tls(&mut TcpIo(&self.tcp)) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        self.flush()?;
        for _ in 0..64 {
            // Persist partial prefixes and bodies across readiness notifications and timeouts.
            let target = if self.prefix_len < 2 {
                &mut self.prefix[self.prefix_len..]
            } else {
                &mut packet[self.received..self.body_len]
            };
            match self.session.reader().read(target) {
                Ok(0) => {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "DoT connection closed",
                    ));
                }
                Ok(length) => {
                    if self.prefix_len < 2 {
                        self.prefix_len += length;
                        if self.prefix_len == 2 {
                            self.body_len = usize::from(u16::from_be_bytes(self.prefix));
                            if self.body_len < 12 || self.body_len > packet.len() {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "invalid DNS stream frame length",
                                ));
                            }
                        }
                    } else {
                        self.received += length;
                        if self.received == self.body_len {
                            let length = self.body_len;
                            self.prefix_len = 0;
                            self.received = 0;
                            return Ok(length);
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    match self.session.read_tls(&mut TcpIo(&self.tcp)) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "DoT connection closed mid-stream",
                            ));
                        }
                        Ok(_) => {
                            self.session
                                .process_new_packets()
                                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
                        }
                        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                    self.flush()?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(ErrorKind::WouldBlock.into())
    }
}

// Rustls keeps partial encrypted writes; Tokio keeps readiness accounting on the underlying socket.
struct TcpIo<'a>(&'a TcpStream);
impl Read for TcpIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(buffer)
    }
}
impl Write for TcpIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.try_write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
