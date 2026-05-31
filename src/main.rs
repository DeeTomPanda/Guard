use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use clap::Parser;

use crate::server::model::Findings;

mod server;
mod cli;

pub struct AppState {
    pub results: HashMap<String, Vec<Findings>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            results: HashMap::new(),
        }
    }
}

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
        
            open::that(format!(
                "http://localhost:3000/results/{}", 
                scan_id
            )).unwrap();
        }
    }
}
