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
    r_i: u64,
    w_i: u64,
}

impl Connect {
    pub fn new(stream: TcpStream) -> Self {
        Connect {
            stream,
            crypto: None,
            r_i: 0,
            w_i: 0
        }
    }
    pub fn new_with_crypto(stream: TcpStream, crypto: Box<dyn Crypto + Send>) -> Self {
        Connect {
            stream,
            crypto: Some(crypto),
            r_i: 0,
            w_i: 0
        }
    }
    pub fn set_crypto(&mut self, crypto: Box<dyn Crypto + Send>) {
        self.crypto = Some(crypto);
        self.r_i = 0;
        self.w_i = 0;
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
        self.r_i = self.r_i.wrapping_add(n as u64);
        let mut res = Vec::from(&buf[0..n]);
        Ok(res)
    }
    pub async fn decrypt_read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut res = self.read().await?;
        if let Some(c) = &mut self.crypto {
            res = c.decrypt(res.as_slice(), self.r_i);
        } else {
            return Err(util::error("请使用 set_crypto"));
        }
        Ok(res)
    }
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.w_i = self.w_i.wrapping_add(data.len() as u64);
        return self.stream.write_all(data).await;
    }
    pub async fn encrypt_write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Some(c) = &mut self.crypto {
            let encrypt_data = c.encrypt(data, self.w_i);
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
                data = c.encrypt(data.as_slice(), self.w_i);
            } else {
                return Err(util::error("请使用 set_crypto"));
            }

            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
            self.w_i = self.w_i.wrapping_add(data.len() as u64);
            // self.stream.flush().await?;
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
                data = c.decrypt(data.as_slice(), connect.r_i);
            } else {
                return Err(util::error("请使用 set_crypto"));
            }
            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
            self.w_i = self.w_i.wrapping_add(data.len() as u64);
            // self.stream.flush().await?;
        }
        Ok(())
    }
}

pub trait Crypto {
    fn encrypt(&mut self, data: &[u8], index: u64) -> Vec<u8>;
    fn decrypt(&mut self, encrypt_data: &[u8], index: u64) -> Vec<u8>;
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
    fn encrypt(&mut self, data: &[u8], index: u64) -> Vec<u8> {
        let mut res = data.to_vec();
        res.iter_mut().enumerate().for_each(|(i, x)| {
            *x = x.wrapping_sub(self.key[((index as usize).wrapping_add(i)) % self.key.len()])
        });
        return res;
    }
    fn decrypt(&mut self, encrypt_data: &[u8], index: u64) -> Vec<u8> {
        let mut res = encrypt_data.to_vec();
        let index = index.wrapping_sub(res.len() as u64);
        res.iter_mut().enumerate().for_each(|(i, x)| {
            *x = x.wrapping_add(self.key[(index as usize).wrapping_add(i) % self.key.len()])
        });
        return res;
    }
}
