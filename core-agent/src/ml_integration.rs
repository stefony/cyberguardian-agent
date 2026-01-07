use crate::backend_client::BackendClient;
use crate::config::Config;

pub fn scan_file(file_path: &str) -> Result<(u8, String), String> {
    // Load configuration from config.json
    let config = Config::load()?;
    
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;
    
    rt.block_on(async {
        let client = BackendClient::new(
            config.backend_url,
            config.license_key
        );
        
        match client.scan_file(file_path).await {
            Ok(response) => {
                println!("🔍 Backend YARA scan: score={}, matches={}", 
                    response.threat_score, 
                    response.yara_matches.len()
                );
                
                let score = if response.threat_score < 0 {
                    0
                } else if response.threat_score > 100 {
                    100
                } else {
                    response.threat_score as u8
                };
                
                Ok((score, response.threat_category))
            }
            Err(e) => {
                println!("⚠️ ML scan failed: {}", e);
                Err(format!("Backend scan failed: {}", e))
            }
        }
    })
}