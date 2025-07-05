use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_echo() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    println!("Listening on {}", socket.local_addr().unwrap());

    let remote_addr = "127.0.0.1:53".parse::<SocketAddr>().unwrap();

    socket.send_to(b"Hello, world!", remote_addr).await.unwrap();

    let mut buf = [0; 1024];
    let (amt, src) = socket.recv_from(&mut buf).await.unwrap();

    assert_eq!(amt, 13);
    assert_eq!(src, remote_addr);
    assert_eq!(String::from_utf8_lossy(&buf[..amt]), "Hello, world!");
}
