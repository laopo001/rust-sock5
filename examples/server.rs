use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use test_r::connect::{Connect, CryptoProxy};
use test_r::util::{self, alias, create_secret_public, get_publickey, resolve_up_ip_port};

async fn accept(mut stream: TcpStream) -> std::io::Result<()> {
    let mut connect = Connect::new(stream);

    // 交换key
    let (secret, public) = create_secret_public();
    let remote_public = connect.read().await?;
    connect.write(&public.to_bytes()).await?;
    let shared_secret = secret.diffie_hellman(&get_publickey(remote_public));
    // dbg!(&shared_secret.as_bytes());
    connect.set_crypto(Box::new(CryptoProxy::new(shared_secret.as_bytes())));

    let (ip, port, host) = resolve_up_ip_port(&mut connect).await?;
    let addr = connect.stream.local_addr()?;
    println!("{} => {}:{} host:{}", addr, &ip, &port, &host);

    let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;
    let mut real_connect = Connect::new(real_stream);

    real_connect.set_crypto(Box::new(CryptoProxy::new(shared_secret.as_bytes())));

    let (ar, aw) = (alias(&connect), alias(&connect));
    let (br, bw) = (alias(&real_connect), alias(&real_connect));
    aw.encrypt_copy(br).race(bw.decrypt_copy(ar)).await?;

    Ok(())
}

async fn app(args: Args) -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:".to_string() + &args.port.to_string()).await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;
        task::spawn(accept(stream));
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
}

fn main() {
    let args = Args::parse();
    dbg!(&args);
    // log4rs::init_file("/home/ldh/Projects/test-r/log4rs.server.yaml", Default::default()).unwrap();

    task::block_on(app(args));
}
