use anyhow::Result;

use clap::Parser;

use futures_util::stream::StreamExt;

use rustls::{Certificate, PrivateKey};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::select;
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
    let certs = vec![Certificate(include_bytes!("../../common/cer").to_vec())];
    let key = PrivateKey(include_bytes!("../../common/key").to_vec());
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
        let span = info_span!(
            "connection",
            remote = %conn.remote_address(),
        );
        let fut = handle_connection(conn);
        tokio::spawn(
            async move {
                if let Err(e) = fut.await {
                    error!(
                        "connection failed: handle_connection {reason}",
                        reason = e.to_string()
                    )
                }
            }
            .instrument(span),
        );
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        connection: _,
        mut bi_streams,
        ..
    } = conn.await?;

    while let Some(stream) = bi_streams.next().await {
        match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed");
                break;
            }
            Err(e) => {
                error!("connection error {}", e);
                break;
            }
            Ok(mut stream) => {
                match resolve_up_ip_port(&mut stream).await {
                    Ok(ip) => {
                        tokio::spawn(
                            async move {
                                info!("remote host:{}", &ip.to_string());
                                if let Ok(mut real_stream) =
                                    TcpStream::connect(ip.to_string()).await
                                {
                                    copy(&mut real_stream, &mut stream)
                                        .await
                                        .unwrap_or_default()
                                } else {
                                    error!("remote host:{}", &ip.to_string());
                                    // stream.0.finish().await.unwrap_or_default();
                                }
                            }
                            .instrument(info_span!("request")),
                        );
                    }
                    Err(err) => {
                        error!("解析ip失败 {}", err);
                        // stream.0.finish().await.unwrap_or_default();
                        continue;
                    }
                }
            }
        };
    }

    Ok(())
}

pub async fn resolve_up_ip_port(
    (_send, recv): &mut (quinn::SendStream, quinn::RecvStream),
) -> Result<IpAddr> {
    let mut buf = [0; 1];
    let n = recv.read(&mut buf[..]).await?.unwrap();
    let buffer = buf[0..n].to_vec();

    if buffer[0] == 1 {
        let len = std::mem::size_of::<common::CommandIpv4Addr>();
        let mut buf = vec![0; len];
        recv.read_exact(&mut buf[..]).await?;
        let ip4: common::CommandIpv4Addr = bincode::deserialize(&buf[..]).unwrap();
        Ok(IpAddr::V4(ip4.0))
    } else if buffer[0] == 2 {
        let len = std::mem::size_of::<common::CommandIpv6Addr>();
        let mut buf = vec![0; len];
        recv.read_exact(&mut buf[..]).await?;
        let ip6: common::CommandIpv6Addr = bincode::deserialize(&buf[..]).unwrap();
        Ok(IpAddr::V6(ip6.0))
    } else {
        unimplemented!()
    }
}

pub async fn copy(
    real_stream: &mut TcpStream,
    (send, recv): &mut (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let (mut r, mut w) = tokio::io::split(real_stream);

    select! {
       r1 = tokio::io::copy(recv, &mut w) => {
           r1
       },
       r2 = tokio::io::copy(&mut r,  send) => {
           r2
       }
       else => {
           error!("tokio::io::copy else");
           Ok(0)
       }
    };
    Ok(())
}
