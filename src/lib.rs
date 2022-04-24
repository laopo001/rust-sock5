pub mod accept_connect;
pub mod local_server;
pub mod util;

use dns_lookup::{lookup_addr, lookup_host};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;

