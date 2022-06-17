use std::error::Error;
use async_std::prelude::*;
use std::result::Result;
use async_std::io;
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use std::path::{Path, PathBuf};
use std::io::BufReader;
use std::fs::File;
/// Load the passed certificates file



async fn start() -> Result<(), Box<dyn Error>> {
    use async_std::net::TcpStream;
    use async_tls::TlsConnector;

    let tcp_stream = TcpStream::connect("rust-lang.org:443").await?;
    let connector = TlsConnector::default();
    let mut tls_stream = connector.connect("www.rust-lang.org", tcp_stream).await?;
    // We write our crafted HTTP request to it
    let http_request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", "www.rust-lang.org");
    tls_stream.write_all(http_request.as_bytes()).await?;

    // And read it all to stdout
    let mut stdout = io::stdout();
    io::copy(&mut tls_stream, &mut stdout).await?;

    Ok(())
}

fn main() {
    async_std::task::block_on(start());
}
