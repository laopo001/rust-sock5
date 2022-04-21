use super::*;

pub struct LocalServer {
    pub listener: Option<TcpListener>,

    pub ip_port: String,
}

impl LocalServer {
    pub fn new(ip_port: String) -> Self {
        LocalServer {
            listener: None,
            ip_port,
        }
    }
    pub async fn start(&mut self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.ip_port).await?;
        self.listener = Some(listener);
        Ok(())
    }
}
