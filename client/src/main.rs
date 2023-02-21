mod sock5;
use anyhow::{anyhow, Result};
use common::BiStream;
use std::net::SocketAddr;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
use clap::Parser;
use git_version::git_version;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
const GIT_VERSION: &str = git_version!();
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
    #[clap(short, long, value_parser, default_value = "quic")]
    net: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("start: {} ", GIT_VERSION);
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

    if args.net == "quic" {
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
        info!("connecting to {} at {}", remote, host);
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
            let mut quic_stream_result = conn.open_bi().await;
            if quic_stream_result.is_err() {
                socket.shutdown().await?;
                error!("结束");
                break;
            }
            let mut quic_stream = quic_stream_result.unwrap();
            tokio::spawn(async move {
                sock5::authenticate(&mut socket).await.unwrap();
                match sock5::resolve_up_ip_port(&mut socket).await {
                    Ok(socket_add) => {
                        match socket_add {
                            SocketAddr::V4(ip4) => {
                                let data =
                                    bincode::serialize(&common::CommandSocketAddrV4(ip4)).unwrap();
                                let mut res = vec![1];
                                res.extend((data.len() as u64).to_ne_bytes());
                                quic_stream.0.write(&res).await.unwrap();
                                quic_stream.0.write(&data).await.unwrap();

                                let mut bistream = BiStream(quic_stream.0, quic_stream.1);
                                match tokio::io::copy_bidirectional(&mut socket, &mut bistream)
                                    .await
                                {
                                    Ok(_) => {
                                        info!("copy success");
                                    }
                                    Err(e) => {
                                        error!("copy error {}", e);
                                    }
                                }
                            }
                            SocketAddr::V6(ip6) => {
                                let data =
                                    bincode::serialize(&common::CommandSocketAddrV6(ip6)).unwrap();
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

                                let mut bistream = BiStream(quic_stream.0, quic_stream.1);

                                match tokio::io::copy_bidirectional(&mut socket, &mut bistream)
                                    .await
                                {
                                    Ok(_) => {
                                        info!("copy success");
                                    }
                                    Err(e) => {
                                        error!("copy error {}", e);
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        error!("resolve_up_ip_port error: {}", err);
                    }
                }
            });
        }
        conn.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
    } else {
        loop {
            let (mut socket, _) = listener.accept().await?;
            info!("accepted");
            let remote: SocketAddr = args.server.parse().expect("server 参数出错，请输入ip:port");
            tokio::spawn(async move {
                let mut stream = TcpStream::connect(remote).await.unwrap();
                sock5::authenticate(&mut socket).await.unwrap();
                match sock5::resolve_up_ip_port(&mut socket).await {
                    Ok(socket_add) => match socket_add {
                        SocketAddr::V4(ip4) => {
                            let data =
                                bincode::serialize(&common::CommandSocketAddrV4(ip4)).unwrap();
                            let mut res = vec![1];
                            res.extend((data.len() as u64).to_ne_bytes());
                            stream.write(&res).await.unwrap();
                            stream.write(&data).await.unwrap();

                            match tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
                                Ok(_) => {
                                    info!("copy success");
                                }
                                Err(e) => {
                                    error!("copy error {}", e);
                                }
                            }
                        }
                        SocketAddr::V6(ip6) => {
                            let data =
                                bincode::serialize(&common::CommandSocketAddrV6(ip6)).unwrap();
                            let mut res = vec![2];
                            res.extend((data.len() as u64).to_ne_bytes());

                            stream.write(&res).await.unwrap();
                            stream.write(&data).await.unwrap();

                            match tokio::io::copy_bidirectional(&mut socket, &mut stream).await {
                                Ok(_) => {
                                    info!("copy success");
                                }
                                Err(e) => {
                                    error!("copy error {}", e);
                                }
                            }
                        }
                    },
                    Err(err) => {
                        error!("resolve_up_ip_port error: {}", err);
                    }
                }
            });
        }
    }

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}
