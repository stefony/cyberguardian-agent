use reqwest::Client;
use serde::{Deserialize, Serialize};

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
       let url = format!("{}/api/signatures/scan/file-desktop", self.base_url);
        
        let response = self.client
            .post(&url)
            .header("X-License-Key", &self.license_key)
            .json(&ScanFileRequest {
                file_path: file_path.to_string(),
            })
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