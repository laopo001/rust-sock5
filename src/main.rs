mod local_server;
use local_server::LocalServer;
mod accept_connect;
use accept_connect::AcceptConnect;
mod util;
use dns_lookup::{lookup_addr, lookup_host};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;

async fn accept(mut stream: TcpStream) -> std::io::Result<()> {
    let mut connect = AcceptConnect::new(stream);
    connect.authenticate().await?;
    let (ip, port, host) = connect.resolve_up_ip_port().await?;
    let addr = connect.stream.local_addr()?;

    eprintln!("{} => {}:{} host:{}", addr, &ip, &port, &host);
    let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;
    link_stream(connect.stream, real_stream).await?;

    Ok(())
}
async fn start() -> std::io::Result<()> {
    let mut server = LocalServer::new("0.0.0.0:7891".to_string());
    server.start().await?;
    let mut incoming = server.listener.as_ref().unwrap().incoming();
    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;

        task::spawn(accept(stream));
    }
    Ok(())
}

fn main() {
    task::block_on(start());
}

pub async fn link_stream(a: TcpStream, b: TcpStream) -> Result<()> {
    let (ar, aw) = &mut (&a, &a);
    let (br, bw) = &mut (&b, &b);
    io::copy(ar, bw).race(io::copy(br, aw)).await?;
    Ok(())
}
