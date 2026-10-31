use super::*;
use crate::config::{QueryOrder, QueryType, RunConfigInput, StopCondition};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

pub(crate) fn tls_configs() -> (Arc<rustls::ClientConfig>, TlsAcceptor) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["dot.test".into()]).unwrap();
    let cert = cert.der().clone();
    let key =
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der())
            .into();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    (Arc::new(client), TlsAcceptor::from(Arc::new(server)))
}

pub(crate) fn config(server: SocketAddr) -> RunConfig {
    RunConfig::try_from(RunConfigInput {
        server,
        transport: Transport::Dot {
            server_name: "dot.test".into(),
        },
        domains_path: "domains.txt".into(),
        max_in_flight: 3,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::Once,
        timeout: Duration::from_secs(2),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap()
}

async fn receive(socket: &mut Socket, buffer: &mut [u8]) -> io::Result<usize> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match socket.try_recv(buffer) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    socket.ready(Interest::READABLE).await?;
                }
                result => return result,
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn frames_survive_split_prefixes_bodies_and_combined_replies() {
    let (client, acceptor) = tls_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = config(listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let mut tls = acceptor
            .accept(listener.accept().await.unwrap().0)
            .await
            .unwrap();
        let length = tls.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        tls.read_exact(&mut query).await.unwrap();
        assert_eq!(query, [7; 29]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&29u16.to_be_bytes());
        frame.extend_from_slice(&query);
        tls.write_all(&frame[..1]).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        tls.write_all(&frame[1..8]).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut tail = frame[8..].to_vec();
        tail.extend_from_slice(&frame);
        tls.write_all(&tail).await.unwrap();
        tls.flush().await.unwrap();
    });
    let mut socket = Socket::connect_with_config(&cfg, client, "dot.test".into())
        .await
        .unwrap();
    assert_eq!(socket.try_send(&[7; 29]).unwrap(), 29);
    let mut buffer = vec![0; 65_535];
    for _ in 0..2 {
        assert_eq!(receive(&mut socket, &mut buffer).await.unwrap(), 29);
        assert_eq!(&buffer[..29], &[7; 29]);
    }
    assert_eq!(
        receive(&mut socket, &mut buffer).await.unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
    server.await.unwrap();
}

#[tokio::test]
async fn rejects_wrong_certificate_identity_and_untrusted_ca() {
    for trust_test_ca in [true, false] {
        let (client, acceptor) = tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = config(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = acceptor.accept(listener.accept().await.unwrap().0).await;
        });
        let result = if trust_test_ca {
            Socket::connect_with_config(&cfg, client, "wrong.test".into()).await
        } else {
            Socket::connect_tls(&cfg).await
        };
        assert!(result.is_err(), "certificate verification must fail");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_short_frames_and_eof_inside_a_frame() {
    for bytes in [vec![0, 0], vec![0, 11], vec![0, 29, 1, 2, 3]] {
        let (client, acceptor) = tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = config(listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut tls = acceptor
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            tls.write_all(&bytes).await.unwrap();
            tls.flush().await.unwrap();
        });
        let mut socket = Socket::connect_with_config(&cfg, client, "dot.test".into())
            .await
            .unwrap();
        let error = receive(&mut socket, &mut [0; 65_535]).await.unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::InvalidData | ErrorKind::UnexpectedEof
        ));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn setup_timeout_includes_a_stalled_tls_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut input = config(listener.local_addr().unwrap());
    // A TCP listener alone accepts the connect but never completes a TLS handshake.
    input = RunConfig::try_from(RunConfigInput {
        server: input.server(),
        transport: input.transport().clone(),
        domains_path: "domains.txt".into(),
        max_in_flight: 1,
        workers: 1,
        threads: Some(1),
        stop_condition: StopCondition::Once,
        timeout: Duration::from_millis(30),
        default_query_type: QueryType::A,
        order: QueryOrder::Sequential,
    })
    .unwrap();
    let result = Socket::connect_tls(&input).await;
    assert!(matches!(result, Err(error) if error.kind() == ErrorKind::TimedOut));
}
