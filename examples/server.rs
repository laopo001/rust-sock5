use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use dns_lookup::{lookup_addr, lookup_host};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use test_r::accept_connect::AcceptConnect;
use test_r::connect::Connect;
use test_r::util::{
    self, alias, create_secret_public, get_publickey,
    resolve_up_ip_port,
};

async fn accept(mut stream: TcpStream) -> std::io::Result<()> {
    let mut connect = Connect::new(stream);

    let (ip, port, host) = resolve_up_ip_port(&mut connect).await?;
    let addr = connect.stream.local_addr()?;
    eprintln!("{} => {}:{} host:{}", addr, &ip, &port, &host);

    let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;
    let mut real_connect = Connect::new(real_stream);

    let (ar, aw) = (alias(&connect), alias(&connect));
    let (br, bw) = (alias(&real_connect), alias(&real_connect));
    ar.copy(bw).race(br.copy(aw)).await?;

    Ok(())
}

async fn app() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9998").await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;
        task::spawn(accept(stream));
    }
    Ok(())
}

fn main() {
    // log4rs::init_file("/home/ldh/Projects/test-r/log4rs.server.yaml", Default::default()).unwrap();

    task::block_on(app());
}
