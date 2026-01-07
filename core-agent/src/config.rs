use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub license_key: String,
    pub backend_url: String,
    pub monitored_paths: Vec<String>,
    pub auto_quarantine: bool,
    pub threat_threshold: u8,
    pub sync_interval: u64,
}

impl Config {
    /// Load configuration from config.json file
    pub fn load() -> Result<Self, String> {
        let config_path = "config.json";
        
        // Check if config file exists
        if !Path::new(config_path).exists() {
            return Err(format!("Config file not found: {}", config_path));
        }
        
        // Read file content
        let content = fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        
        // Parse JSON
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config JSON: {}", e))?;
        
        // Validate license key is not empty
        if config.license_key.is_empty() {
            return Err("License key is empty in config.json. Please add a valid license key.".to_string());
        }
        
        Ok(config)
    }
    
    /// Save configuration to config.json file
    pub fn save(&self) -> Result<(), String> {
        let config_path = "config.json";
        
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        
        fs::write(config_path, json)
            .map_err(|e| format!("Failed to write config file: {}", e))?;
        
        Ok(())
    }
    
    /// Create default config (for first run)
    pub fn default() -> Self {
        Self {
            license_key: String::new(),
            backend_url: "http://localhost:8000".to_string(),
            monitored_paths: vec![],
            auto_quarantine: false,
            threat_threshold: 80,
            sync_interval: 10,
        }
    }
}