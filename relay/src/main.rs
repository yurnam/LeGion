use privacy_relay::{AppState, default_addr, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new_at_path("relay/data/relay.sqlite3")?;
    serve(default_addr(), state).await?;
    Ok(())
}
