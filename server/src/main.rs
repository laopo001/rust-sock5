use std::net::ToSocketAddrs;
use std::sync::Arc;
use futures_util::stream::StreamExt;
mod certificate;

use quinn::{Endpoint, EndpointConfig, Incoming, ServerConfig};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certs = certificate::load_certificates("rc.dadigua.men/rc.dadigua.men.cer")?;
    let key = certificate::load_private_key("rc.dadigua.men/rc.dadigua.men.key")?;
    let listen = "127.0.0.1:12345".to_socket_addrs()?.next().unwrap();
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let (endpoint, mut incoming) = quinn::Endpoint::server(server_config, listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = incoming.next().await {
        dbg!(conn.remote_address());
        // info!("connection incoming");
        // let fut = handle_connection(root.clone(), conn);
        // tokio::spawn(async move {
        //     if let Err(e) = fut.await {
        //         error!("connection failed: {reason}", reason = e.to_string())
        //     }
        // });
    }


    return Ok(());
}
