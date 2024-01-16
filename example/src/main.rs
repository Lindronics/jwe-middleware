#[tokio::main]
pub async fn main() {
    let server = example::Server::default();
    println!("Listening on {}", server.address);
    server.join_handle.await.unwrap().unwrap();
}
