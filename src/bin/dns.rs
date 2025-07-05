use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let socket = UdpSocket::bind("0.0.0.0:53").await.unwrap();
    println!("DNS Server listening on {}", socket.local_addr().unwrap());

    loop {
        let mut buf = [0; 1024];
        let (amt, src) = socket.recv_from(&mut buf).await.unwrap();
        println!("Received {} bytes from {}", amt, src);

        let hex_str = hex::encode(&buf[..amt]);
        println!("{}", hex_str);
    }
}
