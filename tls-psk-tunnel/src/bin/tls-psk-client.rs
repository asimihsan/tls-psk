// References
//
// "In TLSv1.3 the client selects a “group” that it will use for key exchange. OpenSSL only
// supports ECDHE groups for this." [3]
//
// [1] https://github.com/alexcrichton/tokio-openssl/blob/master/tests/google.rs
// [2] https://stackoverflow.com/questions/58719595/how-to-do-tls-1-3-psk-using-openssl
// [3] https://wiki.openssl.org/index.php/TLS1.3

use std::error::Error;
use std::net::ToSocketAddrs;
use std::pin::Pin;

use bytes::Bytes;
use eyre::{Result, WrapErr};
use futures::future;
use openssl::ssl::{SslConnector, SslMethod, SslMode, SslOptions};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn client_process(mut input_stream: TcpStream) -> Result<()> {
    println!("client process starting...");

    println!("client TCP connecting to server...");
    let addr = "127.0.0.1:4433".to_socket_addrs().unwrap().next().unwrap();
    let output_stream = TcpStream::connect(&addr).await?;
    println!("client TCP connected to server...");

    println!("client TLS connecting to server...");
    let connector = create_ssl_connector()?;
    let config = connector.configure()?;
    let mut output_stream = tokio_openssl::connect(config, "<no domain>", output_stream).await?;
    println!("client TLS connected to server.");

    println!("client copying...");
    let (mut input_stream_rd, mut input_stream_wr) = tokio::io::split(input_stream);
    let (mut output_stream_rd, mut output_stream_wr) = tokio::io::split(output_stream);
    let handle1 = tokio::spawn(async move {
        println!("copy from input to output starting");
        tokio::io::copy(&mut input_stream_rd, &mut output_stream_wr).await;
        println!("copy from input to output finished");
    });
    let handle2 = tokio::spawn(async move {
        println!("copy from output to input starting");
        tokio::io::copy(&mut output_stream_rd, &mut input_stream_wr).await;
        println!("copy from output to input finished");
    });
    handle1.await?;
    // handle2.await?;

    println!("client process finishing.");
    Ok(())
}

fn get_psk_bytes() -> Result<Bytes> {
    let server_psk_bytes = vec![0x1A, 0x2B, 0x3C, 0x4D];
    Ok(Bytes::from(server_psk_bytes))
}

fn create_ssl_connector() -> Result<SslConnector> {
    let client_identity = "Client #1";
    let client_psk_bytes = get_psk_bytes()?;
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

    Ok(ssl_connector_builder.build())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world client!");
    openssl::init();

    let mut listener = TcpListener::bind("127.0.0.1:1133").await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            match client_process(stream).await {
                Ok(_) => {}
                Err(e) => println!("client failed to process stream: {:?}", e),
            }
        });
    }

    Ok(())
}
