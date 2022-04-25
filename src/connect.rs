use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use log::{info, warn};
use std::fmt::format;
use std::io::{Error, ErrorKind};

use crate::util;
pub struct Connect {
    pub stream: TcpStream,
    pub crypto: Option<Box<dyn Crypto + Send>>,
}

impl Connect {
    pub fn new(stream: TcpStream) -> Self {
        Connect {
            stream,
            crypto: None,
        }
    }
    pub fn new_with_crypto(stream: TcpStream, crypto: Box<dyn Crypto + Send>) -> Self {
        Connect {
            stream,
            crypto: Some(crypto),
        }
    }
    pub fn set_crypto(&mut self, crypto: Box<dyn Crypto + Send>) {
        self.crypto = Some(crypto);
    }
    pub async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = [0; 1024];
        let n = self.stream.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("error: {}  {}:{}:{}", "n == 0", file!(), line!(), column!(),),
            ));
        }
        let mut res = Vec::from(&buf[0..n]);
        Ok(res)
    }
    pub async fn decrypt_read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut res = self.read().await?;
        if let Some(c) = &mut self.crypto {
            res = c.decrypt(res.as_slice());
        } else {
            return Err(util::error("请使用 set_crypto"));
        }
        Ok(res)
    }
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        return self.stream.write_all(data).await;
    }
    pub async fn encrypt_write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Some(c) = &mut self.crypto {
            let encrypt_data = c.encrypt(data);
            return self.write(encrypt_data.as_slice()).await;
        } else {
            return Err(util::error("请使用 set_crypto"));
        }
    }
    pub async fn copy(self: &mut Connect, connect: &mut Connect) -> std::io::Result<()> {
        loop {
            let data = match connect.read().await {
                Ok(data) => data,
                Err(err) => {
                    return Err(err);
                }
            };

            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
    pub async fn encrypt_copy(&mut self, connect: &mut Connect) -> std::io::Result<()> {
        loop {
            let mut data = match connect.read().await {
                Ok(data) => data,
                Err(err) => {
                    return Err(err);
                }
            };
            if let Some(c) = &mut self.crypto {
                data = c.encrypt(data.as_slice());
            } else {
                return Err(util::error("请使用 set_crypto"));
            }

            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
            self.stream.flush().await?;
        }
        Ok(())
    }
    pub async fn decrypt_copy(&mut self, connect: &mut Connect) -> std::io::Result<()> {
        loop {
            let mut data = match connect.read().await {
                Ok(data) => data,
                Err(err) => {
                    return Err(err);
                }
            };
            if let Some(c) = &mut self.crypto {
                data = c.decrypt(data.as_slice());
            } else {
                return Err(util::error("请使用 set_crypto"));
            }
            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
            self.stream.flush().await?;
        }
        Ok(())
    }
}

pub trait Crypto {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, encrypt_data: &[u8]) -> Vec<u8>;
}

pub struct CryptoProxy {
    key: Vec<u8>,
}
impl CryptoProxy {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}
impl Crypto for CryptoProxy {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut res = data.to_vec();
        // info!("{:?}", &res);
        res.iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = x.wrapping_sub(1));
        return res;
    }
    fn decrypt(&mut self, encrypt_data: &[u8]) -> Vec<u8> {
        let mut res = encrypt_data.to_vec();
        res.iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = x.wrapping_add(1));
        // info!("{:?}", &res);
        return res;
    }
}
