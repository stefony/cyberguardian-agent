use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use chrono::Utc;

/// Windows scheduled task entry result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEntry {
    pub id: String,
    pub task_name: String,
    pub path: String,
    pub status: String,
    pub enabled: bool,
    pub actions: Vec<TaskAction>,
    pub triggers: Vec<TaskTrigger>,
    pub last_run: String,
    pub next_run: String,
    pub author: String,
    pub risk_score: u32,
    pub indicators: Vec<String>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub path: String,
    pub arguments: String,
    pub working_directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String,
    pub enabled: bool,
}

/// Task scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatistics {
    pub total_suspicious: usize,
    pub critical_risk: usize,
    pub high_risk: usize,
    pub medium_risk: usize,
    pub low_risk: usize,
    pub by_status: HashMap<String, usize>,
    pub enabled_count: usize,
    pub disabled_count: usize,
}

/// Suspicious patterns in task actions
const SUSPICIOUS_PATTERNS: &[&str] = &[
    r"\temp\",
    r"\appdata\local\temp\",
    r"\users\public\",
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "bitsadmin",
    "certutil",
    ".vbs",
    ".js",
    ".bat",
    ".ps1",
    "http://",
    "https://",
];

/// Suspicious trigger types (high-risk persistence)
const SUSPICIOUS_TRIGGERS: &[&str] = &[
    "BOOT",
    "LOGON",
    "STARTUP",
];

/// Known legitimate tasks (whitelist)
const WHITELIST: &[&str] = &[
    "microsoft",
    "windows",
    "adobe",
    "google",
    "intel",
    "nvidia",
    "realtek",
    "defender",
];

/// Scan Windows scheduled tasks using PowerShell
#[cfg(target_os = "windows")]
pub fn scan_tasks() -> Result<Vec<TaskEntry>, String> {
    let mut suspicious_tasks = Vec::new();
    
    // PowerShell command to get scheduled tasks
    let ps_command = r#"
        Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} | 
        Select-Object -First 50 TaskName, TaskPath, State, @{Name='Enabled';Expression={$_.Settings.Enabled}} |
        ConvertTo-Json
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
    let tasks: Result<Vec<serde_json::Value>, _> = serde_json::from_str(&stdout);
    
    let tasks = match tasks {
        Ok(t) => t,
        Err(_) => {
            // Try parsing as single object
            if let Ok(single) = serde_json::from_str::<serde_json::Value>(&stdout) {
                vec![single]
            } else {
                return Ok(Vec::new());
            }
        }
    };
    
    for task_data in tasks {
        let task_name = task_data["TaskName"].as_str().unwrap_or("").to_string();
        let task_path = task_data["TaskPath"].as_str().unwrap_or("").to_string();
        
        // State: 1=Disabled, 2=Queued, 3=Ready, 4=Running
        let state_code = task_data["State"].as_i64().unwrap_or(3);
        let status = match state_code {
            1 => "Disabled",
            2 => "Queued",
            3 => "Ready",
            4 => "Running",
            _ => "Unknown",
        }.to_string();
        
        let enabled = task_data["Enabled"].as_bool().unwrap_or(false);
        
        if task_name.is_empty() {
            continue;
        }
        
        // Get full task path
        let full_path = format!("{}{}", task_path, task_name);
        
        // Check if suspicious
        if is_suspicious(&task_name, &full_path) {
            // Create simplified action (we'll get real actions later if needed)
            let actions = vec![TaskAction {
                action_type: "Execute".to_string(),
                path: format!("Task: {}", task_name),
                arguments: String::new(),
                working_directory: String::new(),
            }];
            
            // Determine triggers based on task path
            let triggers = detect_triggers(&full_path);
            
            let task_entry = TaskEntry {
                id: format!("{:x}", md5::compute(&full_path)),
                task_name: task_name.clone(),
                path: full_path.clone(),
                status: status.clone(),
                enabled,
                actions,
                triggers: triggers.clone(),
                last_run: "N/A".to_string(),
                next_run: "N/A".to_string(),
                author: "Unknown".to_string(),
                risk_score: calculate_risk_score(&task_name, &full_path, &triggers, enabled),
                indicators: get_indicators(&task_name, &full_path, &triggers),
                scanned_at: Utc::now().to_rfc3339(),
            };
            
            suspicious_tasks.push(task_entry);
        }
    }
    
    Ok(suspicious_tasks)
}

/// Detect triggers based on task characteristics
fn detect_triggers(task_path: &str) -> Vec<TaskTrigger> {
    let mut triggers = Vec::new();
    let path_lower = task_path.to_lowercase();
    
    if path_lower.contains("logon") || path_lower.contains("startup") {
        triggers.push(TaskTrigger {
            trigger_type: "LOGON".to_string(),
            enabled: true,
        });
    }
    
    if path_lower.contains("boot") {
        triggers.push(TaskTrigger {
            trigger_type: "BOOT".to_string(),
            enabled: true,
        });
    }
    
    // Default trigger if none detected
    if triggers.is_empty() {
        triggers.push(TaskTrigger {
            trigger_type: "DAILY".to_string(),
            enabled: true,
        });
    }
    
    triggers
}

/// Check if a task is suspicious
fn is_suspicious(task_name: &str, task_path: &str) -> bool {
    let name_lower = task_name.to_lowercase();
    let path_lower = task_path.to_lowercase();
    
    // Check whitelist first
    for safe in WHITELIST {
        if path_lower.contains(safe) || name_lower.contains(safe) {
            return false;
        }
    }
    
    // Check for suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS {
        if path_lower.contains(&pattern.to_lowercase()) || name_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }
    
    // Tasks in root path are suspicious
    if task_path == "\\" {
        return true;
    }
    
    false
}

/// Calculate risk score (0-100)
fn calculate_risk_score(task_name: &str, task_path: &str, triggers: &[TaskTrigger], enabled: bool) -> u32 {
    let mut score = 0u32;
    let name_lower = task_name.to_lowercase();
    let path_lower = task_path.to_lowercase();
    
    // High-risk patterns (30 points)
    let high_risk = ["powershell", "cmd.exe", "wscript", "mshta", "download", "http"];
    for pattern in &high_risk {
        if name_lower.contains(pattern) || path_lower.contains(pattern) {
            score += 30;
        }
    }
    
    // Medium-risk patterns (20 points)
    let medium_risk = [r"\temp\", r"\appdata\", r"\users\public\"];
    for pattern in &medium_risk {
        if path_lower.contains(&pattern.to_lowercase()) {
            score += 20;
        }
    }
    
    // Suspicious triggers (15 points each)
    for trigger in triggers {
        for sus_trigger in SUSPICIOUS_TRIGGERS {
            if trigger.trigger_type.contains(sus_trigger) {
                score += 15;
            }
        }
    }
    
    // Enabled tasks are more concerning (10 points)
    if enabled {
        score += 10;
    }
    
    // Tasks in root path (20 points)
    if task_path == "\\" {
        score += 20;
    }
    
    score.min(100)
}

/// Get suspicious indicators
fn get_indicators(task_name: &str, task_path: &str, triggers: &[TaskTrigger]) -> Vec<String> {
    let mut indicators = Vec::new();
    let name_lower = task_name.to_lowercase();
    let path_lower = task_path.to_lowercase();
    
    if path_lower.contains(r"\temp\") || path_lower.contains(r"\users\public\") {
        indicators.push("Located in temporary directory".to_string());
    }
    
    if name_lower.contains("powershell") || name_lower.contains("cmd") || name_lower.contains("script") {
        indicators.push("Uses scripting tool".to_string());
    }
    
    if task_path == "\\" {
        indicators.push("Task in root directory".to_string());
    }
    
    for trigger in triggers {
        for sus_trigger in SUSPICIOUS_TRIGGERS {
            if trigger.trigger_type.contains(sus_trigger) {
                indicators.push(format!("Suspicious trigger: {}", trigger.trigger_type));
                break;
            }
        }
    }
    
    indicators
}

/// Calculate statistics
pub fn calculate_statistics(tasks: &[TaskEntry]) -> TaskStatistics {
    let mut by_status: HashMap<String, usize> = HashMap::new();
    
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut enabled = 0;
    let mut disabled = 0;
    
    for task in tasks {
        *by_status.entry(task.status.clone()).or_insert(0) += 1;
        
        if task.enabled {
            enabled += 1;
        } else {
            disabled += 1;
        }
        
        match task.risk_score {
            80..=100 => critical += 1,
            60..=79 => high += 1,
            40..=59 => medium += 1,
            _ => low += 1,
        }
    }
    
    TaskStatistics {
        total_suspicious: tasks.len(),
        critical_risk: critical,
        high_risk: high,
        medium_risk: medium,
        low_risk: low,
        by_status,
        enabled_count: enabled,
        disabled_count: disabled,
    }
}

/// Non-Windows stub
#[cfg(not(target_os = "windows"))]
pub fn scan_tasks() -> Result<Vec<TaskEntry>, String> {
    Err("Task scanning is only supported on Windows".to_string())
}