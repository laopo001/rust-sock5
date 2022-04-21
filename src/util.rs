use std::io::{Error, ErrorKind, Result};

pub fn error(s: &str) -> std::io::Error {
    let file = file!();
    let line = line!();
    let col = column!();
    println!("error: {} --- {}:{}:{}", s, file, line, col);
    return Error::new(ErrorKind::Other, s);
}
