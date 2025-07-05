use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    println!("Echo server listening on {}", socket.local_addr().unwrap());

    loop {
        let mut buf = [0; 1024];
        let (amt, src) = socket.recv_from(&mut buf).await.unwrap();
        println!("Received {} bytes from {}", amt, src);
        println!("{}", String::from_utf8_lossy(&buf[..amt]));

        socket.send_to(&buf[..amt], src).await.unwrap();
    }
}
