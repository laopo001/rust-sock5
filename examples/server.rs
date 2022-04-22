use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use test_r::accept_connect::AcceptConnect;
use test_r::util::link_stream;

async fn app() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9999").await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;

        let mut connect = AcceptConnect::new(stream);
        let (ip, port, host) = connect.resolve_up_ip_port().await?;
        let addr = connect.stream.local_addr()?;
        eprintln!("{} => {}:{} host:{}", addr, &ip, &port, &host);
        // let mut buf = [0; 5120];
        // let n = connect.stream.read(&mut buf).await?;
        // let res = Vec::from(&buf[0..n]);
        // dbg!(&String::from_utf8(res));
        let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;
        link_stream(connect.stream, real_stream).await?;
    }
    Ok(())
}

fn main() {
    task::block_on(app());
    println!("123");
}

