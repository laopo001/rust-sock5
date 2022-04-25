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
        b.flush().await?;
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
        b.flush().await?;
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
    // let key = Key::from_slice(b"12312313123123123123131231231231");
    // let cipher = Aes256Gcm::new(key);
    // let nonce = Nonce::from_slice(b"unique nonce");
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
    // let key = Key::from_slice(b"12312313123123123123131231231231");
    // let cipher = Aes256Gcm::new(key);
    // let nonce = Nonce::from_slice(b"unique nonce");
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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::connect::Connect;
use dns_lookup::{lookup_addr, lookup_host};

pub fn alias<T>(p: &T) -> &mut T {
    unsafe {
        return std::mem::transmute::<*const T, &mut T>(p as *const T);
    }
}


pub async fn resolve_up_ip_port(
    connect: &mut Connect,
) -> std::io::Result<(String, String, String)> {
    let buffer = connect.read().await?;
    if buffer[0] != 5 {
        return Err(error("只支持sock5"));
    }
    if buffer[1] == 2 {
        return Err(error("只支持TCP UDP"));
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
        connect.write(b.as_slice()).await?;

        let s = IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string();

        Ok((s, port.to_string(), "ipv4".to_string()))
    } else if attr_type == 3 {
        // 域名
        // eprintln!("域名代理");
        let len = buffer[4] as usize;
        let hostname = String::from_utf8(Vec::from(&buffer[5..(5 + len)])).unwrap();

        let port_arr = &buffer[5 + len..5 + len + 2];
        let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;
        let ip: Vec<std::net::IpAddr> = lookup_host(hostname.as_str()).unwrap();
        let mut b = buffer.clone();
        b[1] = 0;
        connect.write(b.as_slice()).await?;
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
        connect.write(b.as_slice()).await?;

        let s = IpAddr::V6(Ipv6Addr::from(ip)).to_string();

        Ok((s, port.to_string(), "ipv6".to_string()))
    } else {
        unimplemented!()
    }
}



pub async fn authenticate(connect: &mut Connect) -> std::io::Result<()> {
    let buffer = connect.read().await?;
    if buffer[0] != 5 {
        return Err(error("只支持sock5"));
    }
    let methods = buffer.get(2..buffer.len()).unwrap().to_vec();
    if methods.contains(&0) {
        connect.write(&[5, 0]).await?;
        return Ok(());
    } else if methods.contains(&2) {
        connect.write(&[5, 2]).await?;
        let buffer = connect.read().await?;
        // https://www.ietf.org/rfc/rfc1929.html  子版本rfc1929
        /*
        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        +----+------+----------+------+----------+
         */
        if buffer[0] != 1 {
            return Err(error("子协商的当前版本是1"));
        }

        let ulen = buffer[1] as usize;
        let username = String::from_utf8(buffer[2..2 + ulen].into()).unwrap();

        let plen = buffer[2 + ulen] as usize;
        let pstart = 2 + ulen + 1;
        let password = String::from_utf8(buffer[pstart..pstart + plen].into()).unwrap();

        eprintln!("username:{},password:{}", &username, &password);
        if (username == "admin" && password == "123456") {
            connect.write(&[1, 0]).await?;
        } else {
            connect.write(&[1, 1]).await?;
            return Err(error("密码错误"));
        }
        return Ok(());
    } else {
        return Err(error("不支持的验证"));
    }
}
