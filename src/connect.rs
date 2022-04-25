use std::fmt::format;

use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use std::io::{Error, ErrorKind};
pub struct Connect {
    pub stream: TcpStream,
    pub crypto: Option<Box<dyn Crypto>>,
}

impl Connect {
    pub fn new(stream: TcpStream) -> Self {
        Connect {
            stream,
            crypto: None,
        }
    }
    pub fn new_with_crypto(stream: TcpStream, crypto: Box<dyn Crypto>) -> Self {
        Connect {
            stream,
            crypto: Some(crypto),
        }
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
        let res = Vec::from(&buf[0..n]);
        Ok(res)
    }
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        return self.stream.write_all(data).await;
    }
    pub async fn copy(&mut self, connect: &mut Connect) -> std::io::Result<()> {
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
    pub async fn encrypt_copy<T>(&mut self, connect: &mut Connect) -> std::io::Result<()> {
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
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "error: {}  {}:{}:{}",
                        "请使用 new_with_crypto",
                        file!(),
                        line!(),
                        column!(),
                    ),
                ));
            }
            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
    pub async fn decrypt_copy<T>(&mut self, connect: &mut Connect) -> std::io::Result<()> {
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
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "error: {}  {}:{}:{}",
                        "请使用 new_with_crypto",
                        file!(),
                        line!(),
                        column!(),
                    ),
                ));
            }
            match self.stream.write_all(data.as_slice()).await {
                Ok(_) => {}
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

pub trait Crypto {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, encrypt_data: &[u8]) -> Vec<u8>;
}

pub struct CryptoProxy {}
impl CryptoProxy {
    pub fn new() -> Self {
        Self {}
    }
}
impl Crypto for CryptoProxy {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut res = data.to_vec();
        res.iter_mut().for_each(|x| *x = x.wrapping_sub(1));
        return res;
    }
    fn decrypt(&mut self, encrypt_data: &[u8]) -> Vec<u8> {
        let mut res = encrypt_data.to_vec();
        res.iter_mut().for_each(|x| *x = x.wrapping_add(1));
        return res;
    }
}
