use async_std::io::{self, ReadExt};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;

async fn app() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7891").await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let mut stream = stream?;
     

        let mut buf = Vec::with_capacity(1024);
        stream.take(1024).read_to_end(&mut buf);

        // println!("{:?}", buf);
        // let mut writer = io::stdout();

        // io::copy(&mut stream, &mut writer).await?;
        // let mut buffer = vec![];
        // let n = stream.read_to_end(&mut buffer).await?;
        dbg!(&buf);
        // dbg!(String::from_utf8(Vec::from(buffer)).unwrap().as_str());
        // dbg!(123123);
        // let contents = "egg hi";
        // let response = format!(
        //     "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        //     contents.len(),
        //     contents
        // );
        // dbg!(response.as_str());
        // stream.write(response.as_bytes()).await?;
        // stream.flush().await?;
    }
    Ok(())
}

fn main() {
    task::block_on(app());
    println!("123");
}
