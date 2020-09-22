// References
// - https://github.com/alexcrichton/tokio-openssl/blob/master/tests/google.rs

use std::error::Error;
use std::net::ToSocketAddrs;

use openssl::ssl::{SslConnector, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

async fn google() -> Result<(), Box<dyn Error>> {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let config = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap();

    let mut stream = tokio_openssl::connect(config, "google.com", stream)
        .await
        .unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    println!("{}", response);
    Ok(())
}

async fn dummy_call() -> Result<(), Box<dyn Error>> {
    println!("Hello, world client!");
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    openssl::init();
    dummy_call().await?;
    google().await?;
    Ok(())
}
