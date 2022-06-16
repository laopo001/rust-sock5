use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use test_r::connect::{Connect, CryptoProxy};
use test_r::util::{self, alias, authenticate, create_secret_public, get_publickey};

async fn accept(mut stream: TcpStream, args: Args) -> std::io::Result<()> {
    let mut connect = Connect::new(stream);
    authenticate(&mut connect).await?;
    let mut realstream = TcpStream::connect(args.server).await?;
    let mut real_connect = Connect::new(realstream);
    // 交换key
    let (secret, public) = create_secret_public();
    real_connect.write(&public.to_bytes()).await?;
    let remote_public = real_connect.read().await?;

    let shared_secret = secret.diffie_hellman(&get_publickey(remote_public));
    // dbg!(&shared_secret.as_bytes());
    connect.set_crypto(Box::new(CryptoProxy::new(shared_secret.as_bytes())));
    real_connect.set_crypto(Box::new(CryptoProxy::new(shared_secret.as_bytes())));

    let (ar, aw) = (alias(&connect), alias(&connect));
    let (br, bw) = (alias(&real_connect), alias(&real_connect));
    aw.decrypt_copy(br).race(bw.encrypt_copy(ar)).await?;
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
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    // log4rs::init_file("/home/ldh/Projects/test-r/log4rs.client.yaml", Default::default()).unwrap();
    task::block_on(start(args));
}
