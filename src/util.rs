use async_std::io::{self, Read, Write};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use log::{info, warn};
use std::io::{Error, ErrorKind, Result};

pub fn error(s: &str) -> std::io::Error {
    let file = file!();
    let line = line!();
    let col = column!();
    println!("error: {} --- {}:{}:{}", s, file, line, col);
    return Error::new(ErrorKind::Other, s);
}
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

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
    let buffer = connect.decrypt_read().await?;
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
        connect.encrypt_write(b.as_slice()).await?;

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
        connect.encrypt_write(b.as_slice()).await?;
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
        connect.encrypt_write(b.as_slice()).await?;

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
