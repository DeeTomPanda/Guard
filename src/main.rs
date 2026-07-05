use chrono::Local;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::detectors::shared::sarif::*;
use crate::server::models::{findings::Findings, symbols::SymbolKind};
use crate::state::AppState;

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
    Analyze {
        path: String,
    },
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
            let scan_id = cli::scan(path, Arc::clone(&state)).await;

            if sarif {
                let file_path = output.unwrap_or_else(|| {
                    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
                    format!("guard-{}-report.sarif", timestamp)
                });

                let state_read = state.read().await;
                if let Some(results) = state_read.results.get(&scan_id) {
                    match to_sarif_json(&results.findings) {
                        Ok(json) => {
                            std::fs::write(file_path, json).unwrap();
                        }
                        Err(e) => {
                            eprintln!("fialed to serialize into SARIF: ({})", e);
                        }
                    }
                }
                return;
            } else {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    server::start_server(state_clone).await;
                });
                // trigger the browser to open the results page
                open::that(format!("http://localhost:3000/#/results/{}", scan_id)).unwrap();
            }
            tokio::signal::ctrl_c().await.unwrap();
        }
        Command::Analyze { path } => {
            let scan_id = cli::scan(path, Arc::clone(&state)).await;
            let state_read = state.read().await;

            if let Some(scan_data) = state_read.results.get(&scan_id) {
                let mut functions = 0;
                let mut methods = 0;
                let mut variables = 0;
                let mut parameters = 0;
                let mut imports = 0;
                let mut classes = 0;

                for symbols in scan_data.symbol_table.symbols.values() {
                    for sym in symbols {
                        match sym.kind {
                            SymbolKind::Function => functions += 1,
                            SymbolKind::Method => methods += 1,
                            SymbolKind::Variable => variables += 1,
                            SymbolKind::Parameter => parameters += 1,
                            SymbolKind::Import => imports += 1,
                            SymbolKind::Class => classes += 1,
                            _ => {}
                        }
                    }
                }

                let total = functions + methods + variables + parameters + imports + classes;

                println!("\nAnalysis complete");
                println!("─────────────────────────────");
                println!("  Functions:  {}", functions);
                println!("  Methods:    {}", methods);
                println!("  Variables:  {}", variables);
                println!("  Parameters: {}", parameters);
                println!("  Imports:    {}", imports);
                println!("  Classes:    {}", classes);
                println!("─────────────────────────────");
                println!("  Total:      {}", total);
            }
        }
    }
}
