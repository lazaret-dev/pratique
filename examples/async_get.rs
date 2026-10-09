//! Fetches a URL with the async client, driven by the crate's own minimal executor.
//!
//!     cargo run --release --example async_get -- https://example.com/
//!
//! The same futures work under any executor (tokio, async-std, smol...): they only use
//! `std::task::Waker`.

use pratique::asyncio::block_on;
use pratique::Client;

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "https://example.com/".to_string());
    let client = match Client::new() {
        Ok(c) => c.proxy_from_env().into_async(),
        Err(e) => {
            eprintln!("cannot load the system root certificates: {e}");
            std::process::exit(1);
        }
    };
    match block_on(client.get(&url)) {
        Ok(resp) => {
            println!("{} {}", resp.status, resp.reason);
            for (name, value) in &resp.headers {
                println!("{name}: {value}");
            }
            println!("\n{} body bytes", resp.body.len());
        }
        Err(e) => {
            eprintln!("request failed: {e}");
            std::process::exit(1);
        }
    }
}
