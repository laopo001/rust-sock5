use async_std::io::{self, Read, Write};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
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
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    decrypt_copy(ar, bw, &cipher)
        .race(encrypt_copy(br, aw, &cipher))
        .await?;
    Ok(())
}

pub async fn link_stream(a: TcpStream, b: TcpStream, key: &[u8]) -> std::io::Result<()> {
    let (ar, aw) = &mut (&a, &a);
    let (br, bw) = &mut (&b, &b);
    // io::copy(ar, bw).race(io::copy(br, aw)).await?;
    let key = Key::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    encrypt_copy(ar, bw, &cipher)
        .race(decrypt_copy(br, aw, &cipher))
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
    cipher: &Aes256Gcm,
) -> std::io::Result<()> {
    let nonce = Nonce::from_slice(b"unique nonce"); //

    loop {
        let mut buf = [0; 51200];
        let n = match a.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                n
            }
            Err(e) => return Err(e),
        };
        let data = cipher
            .encrypt(nonce, &buf[0..n])
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
        // let data = &buf[0..n].to_vec();
        let n = match b.write(data.as_slice()).await {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                n
            }
            Err(e) => return Err(e),
        };
    }

    Ok(())
}
pub async fn decrypt_copy(
    a: &mut &TcpStream,
    b: &mut &TcpStream,
    cipher: &Aes256Gcm,
) -> std::io::Result<()> {
    let nonce = Nonce::from_slice(b"unique nonce"); //
    loop {
        let mut buf = [0; 51200];
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
        let data = cipher
            .decrypt(nonce, &buf[0..n])
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        // let data = &buf[0..n].to_vec();
        let n = match b.write(data.as_slice()).await {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                n
            }
            Err(e) => return Err(e),
        };
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
