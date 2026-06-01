use crate::server::handlers::handler;
use crate::AppState;
use axum::{routing::get, Router};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

pub mod detectors;
pub mod handlers;
pub mod model;
pub mod service;

pub async fn start_server(state: Arc<RwLock<AppState>>) {
    println!("Starting server on http://127.0.0.1:3000");

    let api = Router::new()
        .route("/results/{scan_id}", get(handler::get_results))
        .with_state(state);

    let app = Router::new()
        // API routes under /api
        .nest("/api", api)
        // flutter served under /app
        .nest_service(
            "/app",
            ServeDir::new("dashboard/build/web")
                .not_found_service(ServeFile::new("dashboard/build/web/index.html")),
        )
        // redirect root → /app
        .route(
            "/",
            axum::routing::get(|| async { axum::response::Redirect::to("/app") }),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to port 3000");

    axum::serve(listener, app).await.expect("Server error");
}
