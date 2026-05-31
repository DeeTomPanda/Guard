use crate::AppState;
use axum::{routing::get, Router};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::server::handlers::handler;

pub mod model;
pub mod detectors;
pub mod service;
pub mod handlers;

pub async fn start_server(state: Arc<RwLock<AppState>>) {
    println!("Starting server on http://127.0.0.1:3000");
    let app = Router::new()
        .route("/results/{scan_id}", get(handler::get_results))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
    .await
    .expect("Failed to bind to port 3000 - is it already in use?");

    match axum::serve(listener, app).await{
        Ok(_) => println!("Server stopped gracefully"),
        Err(e) => eprintln!("Server error: {}", e),
    }
}
    