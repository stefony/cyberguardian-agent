//! API Client for communicating with Railway backend
//! Sends process data and receives threat analysis

use serde::{Deserialize, Serialize};
use std::error::Error;

/// Backend API URL (Railway production)
const BACKEND_URL: &str = "https://cyberguardian-backend-production.up.railway.app";

/// Process info structure for API communication
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub exe_path: String,
}

/// API Response structure
#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// Send processes to backend
pub async fn send_processes_to_backend(
    processes: Vec<ProcessInfo>,
    api_token: &str,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    
    let url = format!("{}/api/process-monitor/upload-processes", BACKEND_URL);
    
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&processes)
        .send()
        .await?;
    
    if response.status().is_success() {
        println!("✅ Sent {} processes to backend", processes.len());
        Ok(())
    } else {
        let status = response.status();
        let error_text = response.text().await?;
        Err(format!("Backend error {}: {}", status, error_text).into())
    }
}

/// Test backend connection
pub async fn test_backend_connection(api_token: &str) -> Result<bool, Box<dyn Error>> {
    let client = reqwest::Client::new();
    
    let url = format!("{}/api/process-monitor/health", BACKEND_URL);
    
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .send()
        .await?;
    
    Ok(response.status().is_success())
}