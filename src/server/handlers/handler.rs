use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use tokio::sync::RwLock;

pub async fn get_results(
    Path(scan_id): Path<String>,
    State(state): State<Arc<RwLock<AppState>>>,
) -> impl IntoResponse {
    println!("Received request for scan_id: {}", scan_id);

    let state_read = state.read().await;

    if let Some(scan_result) = state_read.results.get(&scan_id) {
        Json(&scan_result.findings).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
