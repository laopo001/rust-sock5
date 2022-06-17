use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use async_tls::TlsConnector;
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use rustls::ClientConfig;
use std::io::Cursor;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use test_r::connect::{Connect, CryptoProxy};
use test_r::util::{self, alias, authenticate, create_secret_public, get_publickey};

async fn accept(mut stream: TcpStream, args: Args) -> std::io::Result<()> {
    let mut connect = Connect::new(stream);
    authenticate(&mut connect).await?;
    let cafile = &args.cafile;
    let connector = if let Some(cafile) = cafile {
        connector_for_ca_file(cafile).await?
    } else {
        TlsConnector::default()
    };
    let tcp_stream = TcpStream::connect(&args.server).await?;

    // Use the connector to start the handshake process.
    // This consumes the TCP stream to ensure you are not reusing it.
    // Awaiting the handshake gives you an encrypted
    // stream back which you can use like any other.
    let mut tls_stream = connector.connect(&args.server, tcp_stream).await?;

    let connector = if let Some(cafile) = cafile {
        connector_for_ca_file(cafile).await?
    } else {
        TlsConnector::default()
    };


    let (ar, aw) = (alias(&connect.stream), alias(&connect.stream));
    let (br, bw) = (alias(&tls_stream), alias(&tls_stream));
    io::copy(aw, br).race(io::copy(bw, ar)).await?;

    Ok(())
}

async fn start(args: Args) -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:".to_string() + &args.port.to_string()).await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;
        task::spawn(accept(stream, args.clone()));
    }
    Ok(())
}

/// 客户端
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 请输入服务端ip:port
    #[clap(short, long, value_parser)]
    server: String,
    #[clap(short, long, value_parser, default_value_t = 1080)]
    port: u16,
    /// 请输入端口
    #[clap(short, long, value_parser)]
    cafile: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    // log4rs::init_file("/home/ldh/Projects/test-r/log4rs.client.yaml", Default::default()).unwrap();
    task::block_on(start(args));
}

async fn connector_for_ca_file(cafile: &Path) -> io::Result<TlsConnector> {
    let mut config = ClientConfig::new();
    let file = async_std::fs::read(cafile).await?;
    let mut pem = Cursor::new(file);
    config
        .root_store
        .add_pem_file(&mut pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    Ok(TlsConnector::from(Arc::new(config)))
}
