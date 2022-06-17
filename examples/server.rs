use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use async_tls::TlsAcceptor;
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use rustls::internal::pemfile::{certs, rsa_private_keys};
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use test_r::connect::{Connect, CryptoProxy};
use test_r::util::{self, alias, create_secret_public, get_publickey, resolve_up_ip_port2};

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

/// Load the passed keys file
fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

/// Configure the server using rusttls
/// See https://docs.rs/rustls/0.16.0/rustls/struct.ServerConfig.html for details
///
/// A TLS server needs a certificate and a fitting private key
fn load_config(options: &Args) -> io::Result<ServerConfig> {
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;

    // we don't use client authentication
    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        // set this server to use one cert together with the loaded private key
        .set_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(config)
}



async fn accept(mut stream: TcpStream, acceptor: TlsAcceptor) -> std::io::Result<()> {
    let addr = stream.peer_addr()?;
    let handshake = acceptor.accept(stream);
    // The handshake is a future we can await to get an encrypted
    // stream back.
    let mut tls_stream = handshake.await?;

    let (ip, port, host) = resolve_up_ip_port2(&mut tls_stream).await?;

    println!("{} => {}:{} host:{}", addr, &ip, &port, &host);

    let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;

    let (ar, aw) = (alias(&tls_stream), alias(&tls_stream));
    let (br, bw) = (alias(&real_stream), alias(&real_stream));
    io::copy(aw, br).race(io::copy(bw, ar)).await?;

    Ok(())
}

async fn app(args: Args) -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:".to_string() + &args.port.to_string()).await?;
    let mut incoming = listener.incoming();
    let config = load_config(&args)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;
        let acceptor = acceptor.clone();
        task::spawn(accept(stream, acceptor));
    }
    Ok(())
}

/// 服务端
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 请输入端口
    #[clap(short, long, value_parser, default_value_t = 8877)]
    port: u16,
    /// 请输入端口
    #[clap(short, long, value_parser, default_value = "cert")]
    cert: PathBuf,
    /// 请输入端口
    #[clap(short, long, value_parser, default_value = "key")]
    key: PathBuf,
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    // log4rs::init_file("/home/ldh/Projects/test-r/log4rs.server.yaml", Default::default()).unwrap();

    task::block_on(app(args));
}
