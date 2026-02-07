use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use chrono::Utc;

/// Windows service entry result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub id: String,
    pub service_name: String,
    pub display_name: String,
    pub binary_path: String,
    pub startup_type: String,
    pub status: String,
    pub description: String,
    pub risk_score: u32,
    pub indicators: Vec<String>,
    pub dependencies: Vec<String>,
    pub scanned_at: String,
}

/// Service scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatistics {
    pub total_suspicious: usize,
    pub critical_risk: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
    pub by_status: HashMap<String, usize>,
    pub by_startup_type: HashMap<String, usize>,
}

/// Suspicious patterns in service binary paths
const SUSPICIOUS_PATTERNS: &[&str] = &[
    r"\temp\",
    r"\appdata\local\temp\",
    r"\users\public\",
    "%temp%",
    "%tmp%",
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta",
    "miner",
    "crypto",
    "bitcoin",
    "monero",
    ".tmp",
    ".vbs",
    ".bat",
    ".ps1",
];

/// Known legitimate Windows services (whitelist)
const WHITELIST: &[&str] = &[
    "wuauserv", "windefend", "mpssvc", "wscsvc", "eventlog",
    "dhcp", "dnscache", "lanmanworkstation", "lanmanserver",
    "nsi", "w32time", "bits", "cryptsvc", "msiserver",
    "spooler", "seclogon", "schedule", "themes", "audiosrv",
];

/// Scan Windows services using PowerShell
#[cfg(target_os = "windows")]
pub fn scan_services() -> Result<Vec<ServiceEntry>, String> {
    let mut suspicious_services = Vec::new();
    
    // Simplified PowerShell command (faster)
    let ps_command = r#"
        Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json
    "#;
    
    // Execute PowerShell command
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_command])
        .output()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;
    
    if !output.status.success() {
        return Err("PowerShell command failed".to_string());
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse JSON output
    let services: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&stdout);
    
    let services = match services {
        Ok(s) => s,
        Err(_) => {
            // Try parsing as single object
            if let Ok(single) = serde_json::from_str::<serde_json::Value>(&stdout) {
                vec![single]
            } else {
                return Ok(Vec::new());
            }
        }
    };
    
    for service_data in services {
        let service_name = service_data["Name"].as_str().unwrap_or("").to_string();
        let display_name = service_data["DisplayName"].as_str().unwrap_or("").to_string();
        
        // Status: 1=Stopped, 4=Running
        let status_code = service_data["Status"].as_i64().unwrap_or(0);
        let status = match status_code {
            1 => "Stopped",
            4 => "Running",
            _ => "Unknown",
        }.to_string();
        
        // StartType: 2=Automatic, 3=Manual, 4=Disabled
        let start_type_code = service_data["StartType"].as_i64().unwrap_or(0);
        let start_type = match start_type_code {
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => "Unknown",
        }.to_string();
        
        if service_name.is_empty() {
            continue;
        }
        
        // For now, use service name as binary path (we'll get real path later if needed)
        let binary_path = format!("Service: {}", service_name);
        
        // Check if suspicious
        if is_suspicious(&service_name, &binary_path) {
            let service_entry = ServiceEntry {
                id: format!("{:x}", md5::compute(&service_name)),
                service_name: service_name.clone(),
                display_name,
                binary_path: binary_path.clone(),
                startup_type: start_type.clone(),
                status: status.clone(),
                description: String::new(),
                risk_score: calculate_risk_score(&service_name, &binary_path, &start_type),
                indicators: get_indicators(&service_name, &binary_path),
                dependencies: Vec::new(),
                scanned_at: Utc::now().to_rfc3339(),
            };
            
            suspicious_services.push(service_entry);
        }
    }
    
    Ok(suspicious_services)
}

/// Check if a service is suspicious
fn is_suspicious(service_name: &str, binary_path: &str) -> bool {
    let name_lower = service_name.to_lowercase();
    let path_lower = binary_path.to_lowercase();
    
    // Check whitelist first
    for safe in WHITELIST {
        if name_lower.contains(safe) {
            return false;
        }
    }
    
    // Check for suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS {
        if path_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }
    
    false
}

/// Calculate risk score (0-100)
fn calculate_risk_score(service_name: &str, binary_path: &str, start_type: &str) -> u32 {
    let mut score = 0u32;
    let path_lower = binary_path.to_lowercase();
    let name_lower = service_name.to_lowercase();
    
    // High-risk patterns (30 points)
    let high_risk = ["miner", "crypto", "bitcoin", "monero", "powershell", "cmd.exe"];
    for pattern in &high_risk {
        if path_lower.contains(pattern) || name_lower.contains(pattern) {
            score += 30;
        }
    }
    
    // Medium-risk patterns (20 points)
    let medium_risk = [r"\temp\", r"\appdata\local\temp\", r"\users\public\", ".tmp"];
    for pattern in &medium_risk {
        if path_lower.contains(&pattern.to_lowercase()) {
            score += 20;
        }
    }
    
    // Auto-start is more concerning (10 points)
    if start_type.to_lowercase().contains("automatic") {
        score += 10;
    }
    
    // Non-standard path (15 points)
    if !path_lower.contains(r"c:\windows\") && !path_lower.contains(r"c:\program files") {
        score += 15;
    }
    
    score.min(100)
}

/// Get suspicious indicators
fn get_indicators(service_name: &str, binary_path: &str) -> Vec<String> {
    let mut indicators = Vec::new();
    let path_lower = binary_path.to_lowercase();
    let name_lower = service_name.to_lowercase();
    
    if path_lower.contains(r"\temp\") || path_lower.contains(r"\users\public\") {
        indicators.push("Located in temporary directory".to_string());
    }
    
    if path_lower.contains("powershell") || path_lower.contains("cmd.exe") {
        indicators.push("Uses scripting tool".to_string());
    }
    
    if name_lower.contains("miner") || name_lower.contains("crypto") {
        indicators.push("Cryptocurrency-related".to_string());
    }
    
    if !path_lower.contains(r"c:\windows\") && !path_lower.contains(r"c:\program files") {
        indicators.push("Non-standard path".to_string());
    }
    
    indicators
}

/// Calculate statistics
pub fn calculate_statistics(services: &[ServiceEntry]) -> ServiceStatistics {
    let mut by_status: HashMap<String, usize> = HashMap::new();
    let mut by_startup_type: HashMap<String, usize> = HashMap::new();
    
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    
    for service in services {
        *by_status.entry(service.status.clone()).or_insert(0) += 1;
        *by_startup_type.entry(service.startup_type.clone()).or_insert(0) += 1;
        
        match service.risk_score {
            80..=100 => critical += 1,
            60..=79 => high += 1,
            40..=59 => medium += 1,
            _ => low += 1,
        }
    }
    
    ServiceStatistics {
        total_suspicious: services.len(),
        critical_risk: critical,
        high_risk: high,
        medium_risk: medium,
        low_risk: low,
        by_status,
        by_startup_type,
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
pub fn scan_services() -> Result<Vec<ServiceEntry>, String> {
    Err("Service scanning is only supported on Windows".to_string())
}