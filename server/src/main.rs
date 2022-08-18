use futures_util::stream::StreamExt;
use std::net::ToSocketAddrs;
mod certificate;
use anyhow::{anyhow, bail, Context, Result};
use quinn::{Endpoint, EndpointConfig, Incoming, ServerConfig};
use std::{
    ascii, fs, io,
    net::SocketAddr,
    path::{self, Path, PathBuf},
    str,
    sync::Arc,
};
use tracing::{error, info, info_span};
use tracing_futures::Instrument as _;

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

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
    let certs = certificate::load_certificates("../certificate/cer")?;
    let key = certificate::load_private_key("../certificate/key")?;
    let listen = "127.0.0.1:12345".to_socket_addrs()?.next().unwrap();
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
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    return Ok(());
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
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
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            let fut = handle_request(stream);
            tokio::spawn(
                async move {
                    if let Err(e) = fut.await {
                        error!("failed: {reason}", reason = e.to_string());
                    }
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

async fn handle_request((mut send, recv): (quinn::SendStream, quinn::RecvStream)) -> Result<()> {
    let req = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| anyhow!("failed reading request: {}", e))?;
    let mut escaped = String::new();
    for &x in &req[..] {
        let part = ascii::escape_default(x).collect::<Vec<_>>();
        escaped.push_str(str::from_utf8(&part).unwrap());
    }
    // dbg!(&escaped);
    info!(content = %escaped);
    let resp = b"hello world\n".to_vec();
    // Write the response
    send.write_all(&resp)
        .await
        .map_err(|e| anyhow!("failed to send response: {}", e))?;
    // Gracefully terminate the stream
    send.finish()
        .await
        .map_err(|e| anyhow!("failed to shutdown stream: {}", e))?;
    info!("complete");
    Ok(())
}


