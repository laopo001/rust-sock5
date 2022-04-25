use async_std::io::{self, Read, Write};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use log::{info, warn};
use std::io::{Error, ErrorKind, Result};

pub fn error(s: &str) -> std::io::Error {
    let file = file!();
    let line = line!();
    let col = column!();
    eprintln!("error: {} --- {}:{}:{}", s, file, line, col);
    return Error::new(ErrorKind::Other, s);
}
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

pub async fn link_stream_server(a: TcpStream, b: TcpStream, key: &[u8]) -> std::io::Result<()> {
    let (ar, aw) = &mut (&a, &a);
    let (br, bw) = &mut (&b, &b);
    // io::copy(ar, bw).race(io::copy(br, aw)).await?;

    decrypt_copy(ar, bw, key)
        .race(encrypt_copy(br, aw, key))
        .await?;
    Ok(())
}

pub async fn link_stream(a: TcpStream, b: TcpStream, key: &[u8]) -> std::io::Result<()> {
    let (ar, aw) = &mut (&a, &a);
    let (br, bw) = &mut (&b, &b);
    // io::copy(ar, bw).race(io::copy(br, aw)).await?;

    encrypt_copy(ar, bw, key)
        .race(decrypt_copy(br, aw, key))
        .await?;
    Ok(())
}

pub async fn copy(a: &mut &TcpStream, b: &mut &TcpStream) -> std::io::Result<()> {
    loop {
        let mut buf = [0; 51200];
        let n = a.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let res = Vec::from(&buf[0..n]);
        b.write(res.as_slice()).await?;
    }
    Ok(())
}

pub async fn encrypt_copy(
    a: &mut &TcpStream,
    b: &mut &TcpStream,
    nonce_key: &[u8],
) -> std::io::Result<()> {
    loop {
        let mut buf = [0; 1024];
        let n = match a.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                n
            }
            Err(e) => return Err(e),
        };

        let mut data = &mut buf[0..n].to_vec();
        encrypt_data(&mut data, nonce_key);
        if b.write_all(data.as_slice()).await.is_err() {
            break;
        }
    }

    Ok(())
}
pub async fn decrypt_copy(
    a: &mut &TcpStream,
    b: &mut &TcpStream,
    nonce_key: &[u8],
) -> std::io::Result<()> {
    loop {
        let mut buf = [0; 1024];
        // let n = a.read(&mut buf).await?;
        let n = match a.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                n
            }
            Err(e) => return Err(e),
        };

        let mut data = &mut buf[0..n].to_vec();
        decrypt_data(&mut data, nonce_key);

        if b.write_all(data.as_slice()).await.is_err() {
            break;
        }
    }
    Ok(())
}

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn create_secret_public() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::new(OsRng);
    let public = PublicKey::from(&secret);
    return (secret, public);
}

pub fn get_publickey(buf: Vec<u8>) -> PublicKey {
    let mut res = [0; 32];
    res.copy_from_slice(buf.as_slice());
    unsafe { PublicKey::from(res) }
}

pub fn encrypt_data(data: &mut Vec<u8>, nonce_key: &[u8]) {
    // let key = Key::from_slice(b"921025");
    // let cipher = Aes256Gcm::new(key);
    // let nonce = Nonce::from_slice(nonce_key);
    // let res = cipher
    //     .encrypt(nonce, data.as_slice())
    //     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
    // data.clone_from(&res);

    let k = nonce_key.iter().fold(0, |a, b| (a as u8).wrapping_add(*b));
    info!("encrypt_data: {:?}", &data);
    data.iter_mut().enumerate().for_each(|(i, x)| {
        *x = x.wrapping_sub(if i < 10 { 1 } else { 2 });
    });
   
}
pub fn decrypt_data(data: &mut Vec<u8>, nonce_key: &[u8]) {
    // let key = Key::from_slice(b"921025");
    // let cipher = Aes256Gcm::new(key);
    // let nonce = Nonce::from_slice(nonce_key);
    // let res = cipher
    //     .decrypt(nonce, data.as_slice())
    //     .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
    // data.clone_from(&res);

    let k = nonce_key.iter().fold(0, |a, b| (a as u8).wrapping_add(*b));
    
    data.iter_mut().enumerate().for_each(|(i, x)| {
        *x = x.wrapping_add(if i < 10 { 1 } else { 2 });
    });
    info!("decrypt_data: {:?}", &data);
}
