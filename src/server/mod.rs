use std::sync::Arc;
use tokio::sync::RwLock;

pub mod model;
pub mod service;
pub mod detectors;

pub async fn start_server(state: Arc<RwLock<crate::AppState>>) {
    println!("Starting the server...");
}
