use serde::{Deserialize, Serialize};

use std::net::{SocketAddrV4, SocketAddrV6};

pub struct Command(pub u8, pub u64);
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CommandSocketAddrV4(pub SocketAddrV4);
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CommandSocketAddrV6(pub SocketAddrV6);
