use std::io::{Error, ErrorKind, Result};
use async_std::net::{TcpListener, TcpStream};
use async_std::io;
use async_std::prelude::*;

pub fn error(s: &str) -> std::io::Error {
    let file = file!();
    let line = line!();
    let col = column!();
    eprintln!("error: {} --- {}:{}:{}", s, file, line, col);
    return Error::new(ErrorKind::Other, s);
}


pub async fn link_stream(a: TcpStream, b: TcpStream) -> std::io::Result<()> {
    let (ar, aw) = &mut (&a, &a);
    let (br, bw) = &mut (&b, &b);
    io::copy(ar, bw).race(io::copy(br, aw)).await?;
    Ok(())
}


