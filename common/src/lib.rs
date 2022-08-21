use serde::{Deserialize, Serialize};

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Command(pub u8);
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CommandIpv4Addr(pub Ipv4Addr);
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct CommandIpv6Addr(pub Ipv6Addr);
