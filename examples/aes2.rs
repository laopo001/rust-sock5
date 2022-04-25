use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes;
use crypto::buffer;
fn main() {
    let key = vec![9, 2, 1, 0, 2, 5];
    let iv = vec![0, 0, 0, 0, 0, 0];
    let mut c = cbc_encryptor(
        KeySize::KeySize256,
        key.as_slice(),
        iv.as_slice(),
        blockmodes::PkcsPadding,
    );

    let text = b"hello";
    let mut read_buffer = buffer::RefReadBuffer::new(text);
    let mut buffer = [0; 5];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    c.encrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();
    dbg!(&buffer);

    let mut c = cbc_decryptor(
        KeySize::KeySize256,
        key.as_slice(),
        iv.as_slice(),
        blockmodes::PkcsPadding,
    );

    let mut read_buffer = buffer::RefReadBuffer::new(&buffer);
    let mut buffer = [0; 128];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    c.decrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();
    dbg!(&buffer);
    dbg!(&String::from_utf8(Vec::from(&buffer[0..5])));
}
