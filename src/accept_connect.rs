use super::*;

// https://www.ietf.org/rfc/rfc1928.txt
// sock5 rfc1928
pub struct AcceptConnect {
    pub stream: TcpStream,
}

impl AcceptConnect {
    pub fn new(stream: TcpStream) -> Self {
        AcceptConnect { stream }
    }
    pub async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = [0; 5120];
        let n = self.stream.read(&mut buf).await?;
        let res = Vec::from(&buf[0..n]);
        Ok(res)
    }
    pub async fn authenticate(&mut self) -> std::io::Result<()> {
        let buffer = self.read().await?;
        if buffer[0] != 5 {
            return Err(util::error("只支持sock5"));
        }
        let methods = buffer.get(2..buffer.len()).unwrap().to_vec();
        if methods.contains(&0) {
            self.stream.write(&[5, 0]).await?;
            return Ok(());
        } else if methods.contains(&2) {
            self.stream.write(&[5, 2]).await?;
            let buffer = self.read().await?;
            // https://www.ietf.org/rfc/rfc1929.html  子版本rfc1929
            /*
            +----+------+----------+------+----------+
            |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            +----+------+----------+------+----------+
            | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            +----+------+----------+------+----------+
             */
            if buffer[0] != 1 {
                return Err(util::error("子协商的当前版本是1"));
            }

            let ulen = buffer[1] as usize;
            let username = String::from_utf8(buffer[2..2 + ulen].into()).unwrap();

            let plen = buffer[2 + ulen] as usize;
            let pstart = 2 + ulen + 1;
            let password = String::from_utf8(buffer[pstart..pstart + plen].into()).unwrap();

            eprintln!("username:{},password:{}", &username, &password);
            if (username == "admin" && password == "123456") {
                self.stream.write(&[1, 0]).await?;
            } else {
                self.stream.write(&[1, 1]).await?;
                return Err(util::error("密码错误"));
            }
            return Ok(());
        } else {
            return Err(util::error("不支持的验证"));
        }
    }
    pub async fn resolve_up_ip_port(&mut self) -> std::io::Result<(String, String, String)> {
        let buffer = self.read().await?;
        if buffer[0] != 5 {
            return Err(util::error("只支持sock5"));
        }
        if buffer[1] == 2 {
            return Err(util::error("只支持TCP UDP"));
        }
        let tcp = buffer[1] == 1;
        let attr_type = buffer[3];
        // IPv4地址 4字节长度
        if attr_type == 1 {
            // println!("IP代理");
            let ip = &buffer[4..4 + 4];
            let port_arr = &buffer[8..8 + 2];
            let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;

            let mut b = buffer.clone();
            b[1] = 0;
            self.stream.write(b.as_slice()).await?;

            let s = IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string();

            Ok((s, port.to_string(), "".to_string()))
        } else if attr_type == 3 {
            // 域名
            // println!("域名代理");
            let len = buffer[4] as usize;
            let hostname = String::from_utf8(Vec::from(&buffer[5..(5 + len)])).unwrap();

            let port_arr = &buffer[5 + len..5 + len + 2];
            let port = port_arr[0] as u16 * 256 + port_arr[1] as u16;
            let ip: Vec<std::net::IpAddr> = lookup_host(hostname.as_str()).unwrap();
            let mut b = buffer.clone();
            b[1] = 0;
            self.stream.write(b.as_slice()).await?;
            // connect(ip[0], port);
            let s = ip[0].to_string();
            Ok((s, port.to_string(), hostname))
        } else if attr_type == 4 {
            // IPv6地址 16个字节长度
            unimplemented!()
        } else {
            unimplemented!()
        }
    }
}
