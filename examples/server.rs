use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use test_r::accept_connect::AcceptConnect;
use test_r::util::{
    create_secret_public, get_publickey, link_stream,
    link_stream_server,
};

async fn accept(mut stream: TcpStream) -> std::io::Result<()> {
    let mut connect = AcceptConnect::new(stream);

    let mut public_remote = connect.read().await?;

    // dbg!(&public_remote);

    let (secret, public) = create_secret_public();
    // dbg!(&public.to_bytes());
    connect.stream.write(&public.to_bytes()).await?;

    let shared_secret = secret.diffie_hellman(&get_publickey(public_remote));
    // dbg!(&shared_secret.to_bytes());

    let (ip, port, host) = connect
        .resolve_up_ip_port_decrypt(&shared_secret.to_bytes())
        .await?;
    let addr = connect.stream.local_addr()?;
    eprintln!("{} => {}:{} host:{}", addr, &ip, &port, &host);
    // let mut buf = [0; 5120];
    // let n = connect.stream.read(&mut buf).await?;
    // let res = Vec::from(&buf[0..n]);
    // dbg!(&String::from_utf8(res));
    let mut real_stream = TcpStream::connect(ip + ":" + port.as_str()).await?;
    link_stream_server(connect.stream, real_stream, &shared_secret.to_bytes()).await?;
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
    task::block_on(app());
    println!("123");
}
