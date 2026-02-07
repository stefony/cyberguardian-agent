use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::Utc;

#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Registry entry result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub id: String,
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub value_type: String,
    pub risk_score: u32,
    pub indicators: Vec<String>,
    pub scanned_at: String,
}

/// Registry scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStatistics {
    pub total_suspicious: usize,
    pub critical_risk: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
    pub by_hive: HashMap<String, usize>,
}

/// Autorun registry keys that malware commonly uses
#[cfg(target_os = "windows")]
const AUTORUN_KEYS: &[(&str, &str)] = &[
    // HKEY_LOCAL_MACHINE (System-wide)
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    
    // HKEY_CURRENT_USER (User-specific)
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
];

/// Suspicious patterns in registry values
const SUSPICIOUS_PATTERNS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "certutil.exe",
    r"\AppData\Local\Temp\",
    r"\Users\Public\",
    "%TEMP%",
    "%TMP%",
    "http://",
    "https://",
    ".tmp",
    ".vbs",
    ".js",
    ".bat",
    ".ps1",
];

/// Known legitimate programs (whitelist)
const WHITELIST: &[&str] = &[
    "SecurityHealthSystray.exe",
    "OneDrive.exe",
    "Teams.exe",
    "Spotify.exe",
    "Discord.exe",
    "Skype.exe",
    "chrome.exe",
    "firefox.exe",
    "explorer.exe",
];

/// Scan Windows registry for suspicious autorun entries
#[cfg(target_os = "windows")]
pub fn scan_registry() -> Result<Vec<RegistryEntry>, String> {
    let mut suspicious_entries = Vec::new();
    
    for (hive_name, key_path) in AUTORUN_KEYS {
        let hive = match *hive_name {
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
            _ => continue,
        };
        
        match scan_key(&hive, hive_name, key_path) {
            Ok(mut entries) => suspicious_entries.append(&mut entries),
            Err(e) => {
                eprintln!("Error scanning {}: {}", key_path, e);
                continue;
            }
        }
    }
    
    Ok(suspicious_entries)
}

/// Scan a specific registry key for suspicious entries
#[cfg(target_os = "windows")]
fn scan_key(hive: &RegKey, hive_name: &str, key_path: &str) -> Result<Vec<RegistryEntry>, String> {
    let mut entries = Vec::new();
    
    // Open registry key
    let key = match hive.open_subkey(key_path) {
        Ok(k) => k,
        Err(_) => return Ok(entries), // Key doesn't exist, skip
    };
    
    // Enumerate all values
    for value in key.enum_values() {
        let (value_name, value_data) = match value {
            Ok((name, data)) => (name, data),
            Err(_) => continue,
        };
        
        let value_data_str = format!("{:?}", value_data);
        
        // Check if suspicious
        if is_suspicious(&value_data_str) {
            let entry = RegistryEntry {
                id: format!("{:x}", md5::compute(format!("{}\\{}\\{}", hive_name, key_path, value_name))),
                hive: hive_name.to_string(),
                key_path: key_path.to_string(),
                value_name: value_name.clone(),
                value_data: value_data_str.clone(),
                value_type: format!("{:?}", value_data),
                risk_score: calculate_risk_score(&value_data_str),
                indicators: get_indicators(&value_data_str),
                scanned_at: Utc::now().to_rfc3339(),
            };
            
            entries.push(entry);
        }
    }
    
    Ok(entries)
}

/// Check if a registry value is suspicious
fn is_suspicious(value_data: &str) -> bool {
    let value_lower = value_data.to_lowercase();
    
    // Check whitelist first
    for safe in WHITELIST {
        if value_lower.contains(&safe.to_lowercase()) {
            return false;
        }
    }
    
    // Check for suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS {
        if value_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }
    
    false
}

/// Calculate risk score (0-100) based on suspicious indicators
fn calculate_risk_score(value_data: &str) -> u32 {
    let mut score = 0u32;
    let value_lower = value_data.to_lowercase();
    
    // High-risk patterns (30 points each)
    let high_risk = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "regsvr32.exe"];
    for pattern in &high_risk {
        if value_lower.contains(pattern) {
            score += 30;
        }
    }
    
    // Medium-risk patterns (20 points each)
    let medium_risk = [r"\temp\", r"\appdata\local\temp\", "%temp%", ".tmp", ".vbs", ".bat"];
    for pattern in &medium_risk {
        if value_lower.contains(&pattern.to_lowercase()) {
            score += 20;
        }
    }
    
    // Low-risk patterns (10 points each)
    let low_risk = ["http://", "https://", "download"];
    for pattern in &low_risk {
        if value_lower.contains(pattern) {
            score += 10;
        }
    }
    
    // Cap at 100
    score.min(100)
}

/// Get list of suspicious indicators found in value data
fn get_indicators(value_data: &str) -> Vec<String> {
    let mut indicators = Vec::new();
    let value_lower = value_data.to_lowercase();
    
    if value_lower.contains("cmd.exe") || value_lower.contains("powershell.exe") || value_lower.contains("wscript.exe") {
        indicators.push("Uses scripting/command line tool".to_string());
    }
    
    if value_lower.contains(r"\temp\") || value_lower.contains("%temp%") || value_lower.contains(".tmp") {
        indicators.push("References temporary directory".to_string());
    }
    
    if value_lower.contains("http://") || value_lower.contains("https://") {
        indicators.push("Contains URL".to_string());
    }
    
    if value_lower.contains(".vbs") || value_lower.contains(".js") || value_lower.contains(".bat") || value_lower.contains(".ps1") {
        indicators.push("Script file extension".to_string());
    }
    
    indicators
}

/// Calculate statistics from scan results
pub fn calculate_statistics(entries: &[RegistryEntry]) -> RegistryStatistics {
    let mut by_hive: HashMap<String, usize> = HashMap::new();
    
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    
    for entry in entries {
        // Count by hive
        *by_hive.entry(entry.hive.clone()).or_insert(0) += 1;
        
        // Count by risk level
        match entry.risk_score {
            80..=100 => critical += 1,
            60..=79 => high += 1,
            40..=59 => medium += 1,
            _ => low += 1,
        }
    }
    
    RegistryStatistics {
        total_suspicious: entries.len(),
        critical_risk: critical,
        high_risk: high,
        medium_risk: medium,
        low_risk: low,
        by_hive,
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
pub fn scan_registry() -> Result<Vec<RegistryEntry>, String> {
    Err("Registry scanning is only supported on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_suspicious() {
        assert!(is_suspicious("cmd.exe /c malware.bat"));
        assert!(is_suspicious("C:\\Users\\Public\\malware.exe"));
        assert!(!is_suspicious("C:\\Program Files\\Chrome\\chrome.exe"));
    }
    
    #[test]
    fn test_risk_score() {
        assert!(calculate_risk_score("cmd.exe") >= 30);
        assert!(calculate_risk_score("C:\\Temp\\file.bat") >= 20);
        assert!(calculate_risk_score("http://malicious.com") >= 10);
    }
}