use std::sync::Arc;
use tokio::sync::RwLock;
use clap::Parser;

use crate::server::model::Findings;
use crate::state::AppState;

mod state;
mod server;
mod cli;


#[derive(Parser)]
enum Command {
    Scan { path: String },
    Serve,
}

#[tokio::main]
async fn main() {
    let command=Command::parse();
    
    let state = Arc::new(RwLock::new(AppState::new()));
    
    match command{
        Command::Serve => {
            server::start_server(state).await;
        },
        Command::Scan { path } => {
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                server::start_server(state_clone).await;
            });
            
            let scan_id = cli::scan(path, Arc::clone(&state)).await;
            
            tokio::time::sleep(
                std::time::Duration::from_millis(500)
            ).await;
        
            // trigger the browser to open the results page 
            open::that(format!(
                "http://localhost:3000/#/app/{}", 
                scan_id
            )).unwrap();

          tokio::signal::ctrl_c().await.unwrap();
        }
    }
}
