use axum::{
    extract::{Path, State},
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::AppState;

pub async fn get_results(
    Path(scan_id): Path<String>,               
    State(state): State<Arc<RwLock<AppState>>>, 
) -> impl IntoResponse {
    
    println!("Received request for scan_id: {}", scan_id);
    
    let state_read=state.read().await;
    
    if let Some(findings) = state_read.results.get(&scan_id) {
        Json(findings).into_response() 
    } else {
        StatusCode::NOT_FOUND.into_response() 
    }
}

