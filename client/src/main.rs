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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let listener = TcpListener::bind("0.0.0.0:1080").await?;
    let mut conn = create_conn().await.unwrap();
    loop {
        let (mut socket, _) = listener.accept().await?;
        let mut splitStream = conn
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        tokio::spawn(async move {
            authenticate(&mut socket).await.unwrap();
            create_stream(&mut splitStream, &mut socket).await.unwrap();
        });
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

async fn create_conn() -> Result<Connection> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&rustls::Certificate(fs::read(&"../certificate/cer")?))?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let start = Instant::now();
    let host = "localhost";
    let remote = "127.0.0.1:12345".parse()?;
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
    tokio::select! {
        Ok(_) = tokio::io::copy(recv, &mut w) => {},
        Ok(_) = tokio::io::copy(&mut r,  send) => {}
    }
    // tokio::io::copy(&mut r, &mut send);
    // tokio::io::copy(recv, w);
    return Ok(());
}
