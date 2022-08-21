use anyhow::{anyhow, Result};
use tracing::{error, info};

use dns_lookup::lookup_host;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn authenticate(stream: &mut TcpStream) -> Result<()> {
    let mut buffer = [0; 128];
    let n = stream.read(&mut buffer[..]).await?;
    if buffer[0] != 5 {
        return Err(anyhow!("只支持sock5"));
    }
    let methods = buffer[2..n].to_vec();
    if methods.contains(&0) {
        stream.write(&[5, 0]).await?;
        Ok(())
    } else if methods.contains(&2) {
        stream.write(&[5, 2]).await?;
        let mut buffer = [0; 1024];
        let _n = stream.read(&mut buffer[..]).await?;
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
        Ok(())
    } else {
        return Err(anyhow!("不支持的验证"));
    }
}

pub async fn resolve_up_ip_port(stream: &mut TcpStream) -> Result<IpAddr> {
    let mut buf = [0; 1024];
    let n = stream.read(&mut buf[..]).await.unwrap();
    if n == 0 {
        return Err(anyhow!("resolve_up_ip_port read fail"));
    }
    let buffer = buf[0..n].to_vec();
    if buffer[0] != 5 {
        return Err(anyhow!("只支持sock5"));
    }
    if buffer[1] == 2 {
        return Err(anyhow!("只支持TCP UDP"));
    }
    let _tcp = buffer[1] == 1;
    let attr_type = buffer[3];
    // IPv4地址 4字节长度
    if attr_type == 1 {
        // eprintln!("IP代理");
        let ip = &buffer[4..4 + 4];
        let port_arr = &buffer[8..8 + 2];
        let _port = port_arr[0] as u16 * 256 + port_arr[1] as u16;

        let mut b = buffer.clone();
        b[1] = 0;
        stream.write(b.as_slice()).await?;
        info!("host ipv4: {:?}", b);
        Ok(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])))
    } else if attr_type == 3 {
        // 域名
        // eprintln!("域名代理");
        let len = buffer[4] as usize;
        let hostname = String::from_utf8(Vec::from(&buffer[5..(5 + len)])).unwrap();

        let port_arr = &buffer[5 + len..5 + len + 2];
        let _port = port_arr[0] as u16 * 256 + port_arr[1] as u16;
        let ip: Vec<std::net::IpAddr> = lookup_host(hostname.as_str())
            .map_err(|err| anyhow!("hostname: {} , {}", hostname, err))?;
        let mut b = buffer.clone();
        b[1] = 0;
        stream.write(b.as_slice()).await?;
        info!("host: {:?} ipv6: {:?}", hostname, b);
        Ok(ip[0])
    } else if attr_type == 4 {
        // IPv6地址 16个字节长度
        let ip = unsafe { std::mem::transmute::<&[u8], [u8; 16]>(&buffer[4..20]) };
        let port_arr = &buffer[20..20 + 2];
        let _port = port_arr[0] as u16 * 256 + port_arr[1] as u16;

        let mut b = buffer.clone();
        b[1] = 0;
        stream.write(b.as_slice()).await?;
        info!("host ipv6: {:?}", b);
        Ok(IpAddr::V6(Ipv6Addr::from(ip)))
    } else {
        unimplemented!()
    }
}
