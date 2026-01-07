use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ScanFileRequest {
    pub file_path: String,
}

#[derive(Debug, Deserialize)]
pub struct ScanFileResponse {
    pub scan_id: Option<String>,
    pub threat_detected: bool,
    pub threat_score: i32,
    pub threat_category: String,
    pub yara_matches: Vec<String>,
}

pub struct BackendClient {
    client: Client,
    base_url: String,
    license_key: String,
}

impl BackendClient {
    pub fn new(base_url: String, license_key: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            license_key,
        }
    }
    
    pub async fn scan_file(&self, file_path: &str) -> Result<ScanFileResponse, String> {
        let url = format!("{}/api/signatures/scan/upload-desktop", self.base_url);
        
        // Read file content
        let file_content = fs::read(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        // Get filename from path
        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Create multipart form with file upload
        let part = reqwest::multipart::Part::bytes(file_content)
            .file_name(filename);
        
        let form = reqwest::multipart::Form::new()
            .part("file", part);
        
        let response = self.client
            .post(&url)
            .header("X-License-Key", &self.license_key)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Scan failed with status: {} - {}", status, body));
        }
        
        let result = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        
        Ok(result)
    }
}