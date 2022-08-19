use anyhow::{anyhow, Result};
use quinn::{Connection, NewConnection};
use std::{
    fs,
    io::{self, Write},
    net::ToSocketAddrs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{error, info};
use url::Url;
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    let mut conn = create_conn(args.server.clone()).await.unwrap();
    loop {
        let (mut socket, _) = listener.accept().await?;
        info!("coming");
        if let Ok(mut quic_stream) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))
        {
            authenticate(&mut socket).await.unwrap();
            if let Err(e) = create_stream(&mut quic_stream, &mut socket).await {
                error!("create_stream err {}", e)
            }
        }
        // match conn
        //     .open_bi()
        //     .await
        //     .map_err(|e| anyhow!("failed to open stream: {}", e))
        // {
        //     Ok(mut splitStream) => {
        //         tokio::spawn(async move {
        //             authenticate(&mut socket).await.unwrap();
        //             if let Err(e) = create_stream(&mut splitStream, &mut socket).await {
        //                 error!("create_stream err {}", e)
        //             }
        //         });
        //     }
        //     Err(err) => {
        //         error!("error: {}", err);
        //         panic!("应该是服务器挂了")
        //         // error!("error: {}, 重新创建连接", err);
        //         // conn.close(0u32.into(), b"done");
        //         // conn = create_conn(args.server.clone())
        //         //     .await
        //         //     .expect("create_conn 创建失败");
        //         // let mut splitStream = conn
        //         //     .open_bi()
        //         //     .await
        //         //     .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        //         // tokio::spawn(async move {
        //         //     authenticate(&mut socket).await.unwrap();
        //         //     create_stream(&mut splitStream, &mut socket)
        //         //         .await
        //         //         .expect("create_conn 创建失败");
        //         // });
        //     }
        // }
    }

    Ok(())
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}

async fn authenticate(stream: &mut TcpStream) -> Result<()> {
    let mut buffer = [0; 128];
    let n = stream.read(&mut buffer[..]).await?;
    if buffer[0] != 5 {
        return Err(anyhow!("只支持sock5"));
    }
    let methods = buffer[2..n].to_vec();
    if methods.contains(&0) {
        stream.write(&[5, 0]).await?;
        return Ok(());
    } else if methods.contains(&2) {
        stream.write(&[5, 2]).await?;
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer[..]).await?;
        if buffer[0] != 1 {
            return Err(anyhow!("子协商的当前版本是1"));
        }
        let ulen = buffer[1] as usize;
        let username = String::from_utf8(buffer[2..2 + ulen].into()).unwrap();

        let plen = buffer[2 + ulen] as usize;
        let pstart = 2 + ulen + 1;
        let password = String::from_utf8(buffer[pstart..pstart + plen].into()).unwrap();
        info!("username:{},password:{}", &username, &password);
        if username == "admin" && password == "123456" {
            stream.write(&[1, 0]).await?;
        } else {
            stream.write(&[1, 1]).await?;
            return Err(anyhow!("密码错误"));
        }
        return Ok(());
    } else {
        return Err(anyhow!("不支持的验证"));
    }
}

async fn create_conn(server: String) -> Result<Connection> {
    let mut roots = rustls::RootCertStore::empty();
    let mut vec = include_bytes!("../../certificate/cer").to_vec();
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
    let remote = server.parse().expect("server 参数出错，请输入ip:port");
    info!("connecting to {} at {}", host, remote);
    let new_conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    info!("connected at {:?}", start.elapsed());
    let quinn::NewConnection {
        connection: conn, ..
    } = new_conn;

    return Ok(conn);
}

async fn create_stream(
    (send, recv): &mut (quinn::SendStream, quinn::RecvStream),
    origin_stream: &mut TcpStream,
) -> Result<()> {
    let (mut r, mut w) = tokio::io::split(origin_stream);
    let r = tokio::select! {
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
    r.map(drop)?;
    return Ok(());
}
