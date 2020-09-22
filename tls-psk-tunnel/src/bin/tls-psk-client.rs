// References
// - https://github.com/alexcrichton/tokio-openssl/blob/master/tests/google.rs

use std::error::Error;
use std::net::ToSocketAddrs;

use openssl::ssl::{SslConnector, SslMethod, SslMode, SslOptions};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

async fn client() -> Result<(), Box<dyn Error>> {
    let client_identity = "Client #1";
    let client_psk_bytes: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

    let addr = "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls())?;
    let opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::NO_TLSV1
        | SslOptions::NO_TLSV1_1
        | SslOptions::NO_TLSV1_2
        | SslOptions::NO_DTLSV1
        | SslOptions::NO_DTLSV1_2
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    ssl_connector_builder.set_options(opts);

    let mode = SslMode::AUTO_RETRY
        | SslMode::ACCEPT_MOVING_WRITE_BUFFER
        | SslMode::ENABLE_PARTIAL_WRITE
        | SslMode::RELEASE_BUFFERS;
    ssl_connector_builder.set_mode(mode);

    ssl_connector_builder.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;

    ssl_connector_builder.set_psk_client_callback(
        move |ssl_context, _identity_hint, identity_bytes, psk_bytes| {
            identity_bytes[..client_identity.len()].clone_from_slice(client_identity.as_bytes());
            identity_bytes[client_identity.len()] = 0;
            psk_bytes[..client_psk_bytes.len()].clone_from_slice(&client_psk_bytes[..]);
            Ok(client_psk_bytes.len())
        },
    );

    let config = ssl_connector_builder.build().configure()?;
    let mut stream = tokio_openssl::connect(config, "<no domain>", stream).await?;

    stream.write_all(b"asdf").await?;

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    println!("{}", response);
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world client!");
    openssl::init();
    client().await?;
    Ok(())
}
