mod sock5;
use anyhow::{anyhow, Result};

use std::net::SocketAddr;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use tracing::{error, info};
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// 客户端
#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// 请输入服务端ip:port
    #[clap(short, long, value_parser, default_value = "127.0.0.1:12345")]
    server: String,
    #[clap(short, long, value_parser, default_value_t = 1080)]
    port: u16,
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

    let listener = TcpListener::bind("0.0.0.0:".to_string() + &args.port.to_string()).await?;

    let mut roots = rustls::RootCertStore::empty();
    let vec = include_bytes!("../../common/cer").to_vec();
    roots.add(&rustls::Certificate(vec))?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    const IDLE_TIMEOUT: Duration = Duration::from_millis(100 * 1000);
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_millis(100)));
    client_config.transport = Arc::new(transport_config);

    endpoint.set_default_client_config(client_config);

    let start = Instant::now();
    let host = "localhost";
    let args = Args::parse();
    let remote = args.server.parse().expect("server 参数出错，请输入ip:port");
    info!("connecting to {} at {}", host, remote);
    let new_conn = endpoint
        .connect(remote, host)?
        .await
        .expect("fail create conn");
    info!("connected at {:?}", start.elapsed());
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;

    loop {
        let (mut socket, _) = listener.accept().await?;
        info!("accepted");
        match conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))
        {
            Ok(mut quic_stream) => {
                tokio::spawn(async move {
                    sock5::authenticate(&mut socket).await.unwrap();
                    match sock5::resolve_up_ip_port(&mut socket).await {
                        Ok(socket_add) => {
                            match socket_add {
                                SocketAddr::V4(ip4) => {
                                    let data =
                                        bincode::serialize(&common::CommandSocketAddrV4(ip4))
                                            .unwrap();
                                    let mut res = vec![1];
                                    res.extend((data.len() as u64).to_ne_bytes());
                                    quic_stream.0.write(&res).await.unwrap();
                                    quic_stream.0.write(&data).await.unwrap();

                                    if let Err(e) = stream_copy(&mut quic_stream, &mut socket).await
                                    {
                                        error!("stream copy err {}", e);
                                        return;
                                    }
                                }
                                SocketAddr::V6(ip6) => {
                                    let data =
                                        bincode::serialize(&common::CommandSocketAddrV6(ip6))
                                            .unwrap();
                                    let mut res = vec![2];
                                    res.extend((data.len() as u64).to_ne_bytes());

                                    quic_stream
                                        .0
                                        .write(
                                            &bincode::serialize(
                                                &res, // [&
                                            )
                                            .unwrap(),
                                        )
                                        .await
                                        .unwrap();
                                    quic_stream.0.write(&data).await.unwrap();

                                    if let Err(e) = stream_copy(&mut quic_stream, &mut socket).await
                                    {
                                        error!("stream copy err {}", e);
                                        return;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("{}", err);
                        }
                    }
                });
            }
            Err(e) => {
                error!("failed open_bi stream: {}", e);
                // socket.shutdown().await?;
                break;
            }
        }
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}

async fn stream_copy(
    (send, recv): &mut (quinn::SendStream, quinn::RecvStream),
    origin_stream: &mut TcpStream,
) -> Result<()> {
    // {
    //     let mut buffer = [0; 1024];
    //     let mut take = origin_stream.take(1024);
    //     let n = take.read(&mut buffer).await?;
    //     let str = String::from_utf8(Vec::from(&buffer[..n])).unwrap();
    //     info!(str);

    //     send.write(&buffer[..n]).await?;
    // }
    let (mut r, mut w) = tokio::io::split(origin_stream);

    let client_to_server = async {
        tokio::io::copy(recv, &mut w).await
        // w.shutdown().await
    };

    let server_to_client = async {
        tokio::io::copy(&mut r, send).await
        // send.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}
