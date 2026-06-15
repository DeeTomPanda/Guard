use chrono::Local;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::models::findings::Findings;
use crate::state::AppState;
use crate::server::detectors::shared::sarif::*;

mod cli;
mod server;
mod state;

#[derive(Parser)]
enum Command {
    Scan {
        path: String,

        #[arg(long)]
        sarif: bool,

        #[arg(long)]
        output: Option<String>,
    },
    Serve,
}

#[tokio::main]
async fn main() {
    let command = Command::parse();

    let state = Arc::new(RwLock::new(AppState::new()));

    match command {
        Command::Serve => {
            server::start_server(state).await;
        }
        Command::Scan {
            path,
            sarif,
            output,
        } => {
            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                server::start_server(state_clone).await;
            });

            let scan_id = cli::scan(path, Arc::clone(&state)).await;

            if sarif {
                let file_path = output.unwrap_or_else(|| {
                    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                    format!("guard-{}-report.sarif", timestamp)
                });

                let state_read=state.read().await;
                if let Some(results)=state_read.results.get(&scan_id){
                    match to_sarif_json(&results){
                        Ok(json)=>{
                            std::fs::write(file_path,json).unwrap();
                        },
                        Err(e)=>{
                            eprintln!("fialed to serialize into SARIF: ({})",e);
                        }
                    }

                }

            } else {
                // trigger the browser to open the results page
                open::that(format!("http://localhost:3000/#/results/{}", scan_id)).unwrap();
            }
            tokio::signal::ctrl_c().await.unwrap();
        }
    }
}
