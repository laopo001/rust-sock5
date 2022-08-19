use futures_util::stream::StreamExt;
use std::net::ToSocketAddrs;
mod certificate;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use dns_lookup::{lookup_addr, lookup_host};
use quinn::{Endpoint, EndpointConfig, Incoming, IncomingBiStreams, ServerConfig};
use rustls::{Certificate, PrivateKey};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};
use tokio::net::TcpStream;
use tracing::{error, info, info_span};
use tracing_futures::Instrument as _;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

/// 服务端
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 请输入端口
    /// 请输入服务端ip:port
    #[clap(short, long, value_parser, default_value = "0.0.0.0:12345")]
    server: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    dbg!(&args);
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            // .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing_subscriber::filter::LevelFilter::DEBUG.into()),
            )
            .finish(),
    )
    .unwrap();

    // let certs = certificate::load_certificates("../certificate/cer")?;
    // let key = certificate::load_private_key("../certificate/key")?;
    let certs = vec![Certificate(
        include_bytes!("../../certificate/cer").to_vec(),
    )];
    let key = PrivateKey(include_bytes!("../../certificate/key").to_vec());
    let listen = args.server.to_socket_addrs()?.next().unwrap();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    let (endpoint, mut incoming) = quinn::Endpoint::server(server_config, listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = incoming.next().await {
        info!("connection incoming");
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!(
                    "connection failed: handle_connection {reason}",
                    reason = e.to_string()
                )
            }
        });
    }

    return Ok(());
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let addr = conn.remote_address();
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = conn.await?;

    let span = info_span!(
        "connection",
        remote = %connection.remote_address(),
        protocol = %connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>().unwrap()
            .protocol
            .map_or_else(|| "<none>".into(), |x| String::from_utf8_lossy(&x).into_owned())
    );
    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.

        // println!("{} => {}:{} host:{}", addr, &ip, &port, &host);
        while let Some(stream) = bi_streams.next().await {
            let mut stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };

            tokio::spawn(
                async move {
                    let res = resolve_up_ip_port(&mut stream).await;
                    if res.is_err() {
                        return;
                    }
                    let (ip, port, host) = res.expect("解析ip失败");
                    info!("remote: {}:{} host:{}", &ip, &port, &host);
                    let mut real_stream =
                        TcpStream::connect(ip + ":" + port.as_str()).await.unwrap();

                    copy(&mut real_stream, &mut stream)
                        .await
                        .expect("copy error");
                }
                .instrument(info_span!("request")),
            );
        }
        Ok(())
    }
    .instrument(span)
    .await?;
    Ok(())
}

pub async fn resolve_up_ip_port(
    (send, recv): &mut (quinn::SendStream, quinn::RecvStream),
) -> Result<(String, String, String)> {
    let mut buf = [0; 1024];
    let n = recv.read(&mut buf[..]).await?.expect("test");
    let buffer = buf[0..n].to_vec();
    if buffer[0] != 5 {
        return Err(anyhow!("只支持sock5"));
    }
    if buffer[1] == 2 {
        return Err(anyhow!("只支持TCP UDP"));
    }
    let tcp = buffer[1] == 1;
    let attr_type = buffer[3];
    // IPv4地址 4字节长度
    if attr_type == 1 {
        // eprintln!("IP代理");
        let ip = &buffer[4..4 + 4];
        let port_arr = &buffer[8..8 + 2];
        let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;

        let mut b = buffer.clone();
        b[1] = 0;
        send.write(b.as_slice()).await?;

        let s = IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string();

        Ok((s, port.to_string(), "ipv4".to_string()))
    } else if attr_type == 3 {
        // 域名
        // eprintln!("域名代理");
        let len = buffer[4] as usize;
        let hostname = String::from_utf8(Vec::from(&buffer[5..(5 + len)])).unwrap();

        let port_arr = &buffer[5 + len..5 + len + 2];
        let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;
        let ip: Vec<std::net::IpAddr> = lookup_host(hostname.as_str())
            .map_err(|err| anyhow!("hostname: {} , {}", hostname, err))?;
        let mut b = buffer.clone();
        b[1] = 0;
        send.write(b.as_slice()).await?;
        // connect(ip[0], port);
        let s = ip[0].to_string();
        Ok((s, port.to_string(), hostname))
    } else if attr_type == 4 {
        // IPv6地址 16个字节长度
        let ip = unsafe { std::mem::transmute::<&[u8], [u8; 16]>(&buffer[4..20]) };
        let port_arr = &buffer[20..20 + 2];
        let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;

        let mut b = buffer.clone();
        b[1] = 0;
        send.write(b.as_slice()).await?;

        let s = IpAddr::V6(Ipv6Addr::from(ip)).to_string();

        Ok((s, port.to_string(), "ipv6".to_string()))
    } else {
        unimplemented!()
    }
}

pub async fn copy(
    real_stream: &mut TcpStream,
    (send, recv): &mut (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let (mut r, mut w) = tokio::io::split(real_stream);

    tokio::select! {
       Err(e) = tokio::io::copy(recv, &mut w) => {
        error!("tokio::io::copy err: {}",e)
       },
       Err(e) = tokio::io::copy(&mut r,  send) => {
        error!("tokio::io::copy err: {}",e)
       }
    }

    return Ok(());
}
