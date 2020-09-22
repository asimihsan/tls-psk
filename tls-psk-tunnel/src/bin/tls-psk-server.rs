// References
// - https://github.com/alexcrichton/tokio-openssl/blob/master/tests/google.rs

use std::error::Error;
use std::pin::Pin;

use futures::future;
use openssl::ssl::{SslAcceptor, SslMethod, SslMode, SslOptions};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world server!");

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    let opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        // | SslOptions::NO_SSLV2
        // | SslOptions::NO_SSLV3
        // | SslOptions::NO_TLSV1
        // | SslOptions::NO_TLSV1_1
        // | SslOptions::NO_TLSV1_2
        // | SslOptions::NO_DTLSV1
        // | SslOptions::NO_DTLSV1_2
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    acceptor.set_options(opts);

    let mode = SslMode::AUTO_RETRY
        | SslMode::ACCEPT_MOVING_WRITE_BUFFER
        | SslMode::ENABLE_PARTIAL_WRITE
        | SslMode::RELEASE_BUFFERS;
    acceptor.set_mode(mode);
    acceptor.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;
    acceptor.set_psk_server_callback(|_ssl_context, _client_identity, psk_bytes| {
        psk_bytes[0] = 0x1A;
        psk_bytes[1] = 0x2B;
        psk_bytes[2] = 0x3C;
        psk_bytes[3] = 0x4D;
        let psk_len = 4;
        Ok(psk_len)
    });

    let acceptor = acceptor.build();

    let mut listener = TcpListener::bind("127.0.0.1:4433").await?;
    let stream = listener.accept().await?.0;
    let mut stream = tokio_openssl::accept(&acceptor, stream).await?;

    let mut buf = [0; 4];
    stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"asdf");

    stream.write_all(b"jkl;").await?;

    future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx)).await?;

    Ok(())
}
