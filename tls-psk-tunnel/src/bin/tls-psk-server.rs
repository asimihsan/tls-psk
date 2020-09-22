// References
// - https://github.com/alexcrichton/tokio-openssl/blob/master/tests/google.rs
// - https://tokio.rs/tokio/tutorial/spawning
// - https://docs.rs/eyre/0.6.0/eyre/struct.Report.html

use std::pin::Pin;

use bytes::Bytes;
use eyre::{eyre, Result, WrapErr};
use futures::future;
use openssl::ssl::{SslAcceptor, SslMethod, SslMode, SslOptions};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn process(stream: TcpStream) -> Result<()> {
    let acceptor = create_ssl_acceptor()?;
    let mut stream = tokio_openssl::accept(&acceptor, stream)
        .await
        .wrap_err("failed to set up TLS session")?;

    let mut buf = [0; 4];
    stream
        .read_exact(&mut buf)
        .await
        .wrap_err("failed to read exactly 4 bytes")?;

    if &buf != b"asdf" {
        return Err(eyre!("Client did not write expected 'asdf' pattern"));
    }

    stream
        .write_all(b"jkl;")
        .await
        .wrap_err("failed to write response")?;

    // uncomment this to demonstrate lack of or support for parallelism (see tokio "spawning"
    // tutorial).
    // delay_for(Duration::from_secs(5)).await;

    future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
        .await
        .wrap_err("failed while waiting for shutdown")?;

    println!("served a request");

    Ok(())
}

fn get_psk_bytes() -> Result<Bytes> {
    let server_psk_bytes = vec![0x1A, 0x2B, 0x3C, 0x4D];
    Ok(Bytes::from(server_psk_bytes))
}

fn create_ssl_acceptor() -> Result<SslAcceptor> {
    let server_psk_bytes = get_psk_bytes()?;
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
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
    acceptor.set_options(opts);

    let mode = SslMode::AUTO_RETRY
        | SslMode::ACCEPT_MOVING_WRITE_BUFFER
        | SslMode::ENABLE_PARTIAL_WRITE
        | SslMode::RELEASE_BUFFERS;
    acceptor.set_mode(mode);
    acceptor.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;
    acceptor.set_psk_server_callback(move |_ssl_context, _client_identity, psk_bytes| {
        psk_bytes[..server_psk_bytes.len()].clone_from_slice(&server_psk_bytes[..]);
        Ok(server_psk_bytes.len())
    });

    let acceptor = acceptor.build();
    Ok(acceptor)
}

#[tokio::main]
pub async fn main() -> Result<()> {
    println!("Hello, world server!");
    openssl::init();

    let mut listener = TcpListener::bind("127.0.0.1:4433").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            match process(stream).await {
                Ok(_) => {}
                Err(e) => println!("failed to process stream: {:?}", e),
            }
        });
    }
}
