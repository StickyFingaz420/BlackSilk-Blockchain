use std::net::TcpListener;

fn main() {
    println!("Testing HTTP server binding...");
    
    // Test if we can bind to port 9333
    match TcpListener::bind("127.0.0.1:9333") {
        Ok(listener) => {
            println!("✅ Successfully bound to port 9333");
            drop(listener);
        }
        Err(e) => {
            println!("❌ Failed to bind to port 9333: {}", e);
        }
    }
    
    // Test if we can bind to any available port
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            let addr = listener.local_addr().unwrap();
            println!("✅ Successfully bound to available port: {}", addr.port());
        }
        Err(e) => {
            println!("❌ Failed to bind to any port: {}", e);
        }
    }
}
