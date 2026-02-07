use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use chrono::Utc;

/// Stage 1: File Analysis Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysisStage {
    pub status: String,
    pub file_type: String,
    pub extension: String,
    pub size_bytes: u64,
    pub suspicious: bool,
    pub indicators: Vec<String>,
    pub hash_md5: Option<String>,
}

/// Stage 2: Registry Scan Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryScanStage {
    pub status: String,
    pub has_references: bool,
    pub related_entries: usize,
    pub registry_keys: Vec<String>,
}

/// Stage 3: Service Scan Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceScanStage {
    pub status: String,
    pub has_dependencies: bool,
    pub related_services: usize,
    pub service_names: Vec<String>,
}

/// Stage 4: Task Scan Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskScanStage {
    pub status: String,
    pub has_references: bool,
    pub related_tasks: usize,
    pub task_names: Vec<String>,
}

/// Complete Analysis Result (all 4 stages)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysisResult {
    pub analysis_id: String,
    pub target_path: String,
    pub analyzed_at: String,
    pub stages: AnalysisStages,
    pub threat_level: String,  // "critical" | "high" | "medium" | "low" | "minimal"
    pub risk_score: u32,       // 0-100
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStages {
    pub file_analysis: FileAnalysisStage,
    pub registry_scan: RegistryScanStage,
    pub service_scan: ServiceScanStage,
    pub task_scan: TaskScanStage,
}

/// Backup Entry for removed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepQuarantineBackup {
    pub filename: String,
    pub filepath: String,
    pub analysis_id: String,
    pub target_path: String,
    pub threat_level: String,
    pub risk_score: u32,
    pub backed_up_at: String,
    pub analysis_data: DeepAnalysisResult,
}

/// List of all backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupList {
    pub backups: Vec<DeepQuarantineBackup>,
}

/// Removal Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalRequest {
    pub analysis_id: String,
    pub remove_file: bool,
    pub remove_registry: bool,
    pub remove_services: bool,
    pub remove_tasks: bool,
}

/// Removal Result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalResult {
    pub success: bool,
    pub backup_file: String,
    pub removed_items: RemovedItems,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovedItems {
    pub file_removed: bool,
    pub registry_entries_removed: usize,
    pub services_removed: usize,
    pub tasks_removed: usize,
}

/// Calculate risk score based on all stages
/// Returns: (risk_score: u32, threat_level: String)
pub fn calculate_risk_score(
    file_stage: &FileAnalysisStage,
    registry_stage: &RegistryScanStage,
    service_stage: &ServiceScanStage,
    task_stage: &TaskScanStage,
) -> (u32, String) {
    let mut score: u32 = 0;

    // Stage 1: File Analysis (0-40 points)
    if file_stage.suspicious {
        score += 20; // Base suspicious score
        
        // Add points for specific indicators
        let high_risk_indicators = ["powershell", "cmd.exe", "wscript", "cscript", "temp", "AppData"];
        let indicator_count = file_stage.indicators.iter()
            .filter(|ind| high_risk_indicators.iter().any(|hr| ind.to_lowercase().contains(hr)))
            .count();
        
        score += (indicator_count as u32 * 5).min(20); // Max 20 additional points
    }

    // Stage 2: Registry References (0-20 points)
    if registry_stage.has_references {
        score += 10; // Base registry presence
        score += (registry_stage.related_entries as u32 * 2).min(10); // Max 10 additional
    }

    // Stage 3: Service Dependencies (0-20 points)
    if service_stage.has_dependencies {
        score += 10; // Base service presence
        score += (service_stage.related_services as u32 * 2).min(10); // Max 10 additional
    }

    // Stage 4: Task References (0-20 points)
    if task_stage.has_references {
        score += 10; // Base task presence
        score += (task_stage.related_tasks as u32 * 2).min(10); // Max 10 additional
    }

    // Cap at 100
    score = score.min(100);

    // Determine threat level
    let threat_level = if score >= 80 {
        "critical".to_string()
    } else if score >= 60 {
        "high".to_string()
    } else if score >= 40 {
        "medium".to_string()
    } else if score >= 20 {
        "low".to_string()
    } else {
        "minimal".to_string()
    };

    (score, threat_level)
}

/// Generate recommendations based on analysis
pub fn generate_recommendations(
    threat_level: &str,
    file_stage: &FileAnalysisStage,
    registry_stage: &RegistryScanStage,
    service_stage: &ServiceScanStage,
    task_stage: &TaskScanStage,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    // Always recommend complete removal for suspicious files
    if file_stage.suspicious {
        recommendations.push("Remove target file immediately".to_string());
    }

    if registry_stage.has_references {
        recommendations.push(format!(
            "Clean {} registry entries referencing this file",
            registry_stage.related_entries
        ));
    }

    if service_stage.has_dependencies {
        recommendations.push(format!(
            "Stop and remove {} related Windows services",
            service_stage.related_services
        ));
    }

    if task_stage.has_references {
        recommendations.push(format!(
            "Delete {} scheduled tasks referencing this file",
            task_stage.related_tasks
        ));
    }

    // Add threat-level specific recommendations
    match threat_level {
        "critical" | "high" => {
            recommendations.push("⚠️ CRITICAL: Immediate removal required - high persistence threat".to_string());
            recommendations.push("Perform full system scan after removal".to_string());
        }
        "medium" => {
            recommendations.push("Review file origin and remove if unknown".to_string());
        }
        "low" => {
            recommendations.push("Monitor file activity before deciding on removal".to_string());
        }
        _ => {
            recommendations.push("File appears safe but review recommendations".to_string());
        }
    }

    recommendations
}

/// Generate unique analysis ID
pub fn generate_analysis_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("deep_analysis_{}", timestamp)
}

/// Get backup directory path
pub fn get_backup_dir() -> PathBuf {
    // Store in AppData/Local/CyberGuardian/deep_quarantine_backups
    let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("CyberGuardian");
    path.push("deep_quarantine_backups");
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_minimal() {
        let file_stage = FileAnalysisStage {
            status: "success".to_string(),
            file_type: "text".to_string(),
            extension: "txt".to_string(),
            size_bytes: 1024,
            suspicious: false,
            indicators: vec![],
            hash_md5: None,
        };

        let registry_stage = RegistryScanStage {
            status: "success".to_string(),
            has_references: false,
            related_entries: 0,
            registry_keys: vec![],
        };

        let service_stage = ServiceScanStage {
            status: "success".to_string(),
            has_dependencies: false,
            related_services: 0,
            service_names: vec![],
        };

        let task_stage = TaskScanStage {
            status: "success".to_string(),
            has_references: false,
            related_tasks: 0,
            task_names: vec![],
        };

        let (score, level) = calculate_risk_score(&file_stage, &registry_stage, &service_stage, &task_stage);
        assert_eq!(score, 0);
        assert_eq!(level, "minimal");
    }

    #[test]
    fn test_risk_score_critical() {
        let file_stage = FileAnalysisStage {
            status: "success".to_string(),
            file_type: "executable".to_string(),
            extension: "exe".to_string(),
            size_bytes: 1024000,
            suspicious: true,
            indicators: vec![
                "powershell".to_string(),
                "cmd.exe".to_string(),
                "temp".to_string(),
                "AppData".to_string(),
            ],
            hash_md5: Some("abc123".to_string()),
        };

        let registry_stage = RegistryScanStage {
            status: "success".to_string(),
            has_references: true,
            related_entries: 5,
            registry_keys: vec!["HKLM\\Run".to_string()],
        };

        let service_stage = ServiceScanStage {
            status: "success".to_string(),
            has_dependencies: true,
            related_services: 3,
            service_names: vec!["MaliciousService".to_string()],
        };

        let task_stage = TaskScanStage {
            status: "success".to_string(),
            has_references: true,
            related_tasks: 2,
            task_names: vec!["BadTask".to_string()],
        };

        let (score, level) = calculate_risk_score(&file_stage, &registry_stage, &service_stage, &task_stage);
        assert!(score >= 80, "Score should be critical: {}", score);
        assert_eq!(level, "critical");
    }
}

// ============================================================================
// STAGE 1: FILE ANALYSIS IMPLEMENTATION
// ============================================================================

use std::fs;

/// Stage 1: Analyze file properties and detect suspicious patterns
pub fn analyze_file_stage(file_path: &str) -> Result<FileAnalysisStage, String> {
    let path = std::path::Path::new(file_path);
    
    // Check if file exists
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    // Get file metadata
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to read file metadata: {}", e))?;
    
    let size_bytes = metadata.len();

    // Get file extension
    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Determine file type
    let file_type = determine_file_type(&extension);

    // Calculate MD5 hash
    let hash_md5 = calculate_md5_hash(path).ok();

    // Analyze for suspicious patterns
    let (suspicious, indicators) = analyze_suspicious_patterns(file_path, &extension, size_bytes);

    Ok(FileAnalysisStage {
        status: "success".to_string(),
        file_type,
        extension,
        size_bytes,
        suspicious,
        indicators,
        hash_md5,
    })
}

/// Determine file type based on extension
fn determine_file_type(extension: &str) -> String {
    match extension {
        "exe" | "dll" | "sys" | "drv" | "com" | "scr" => "executable".to_string(),
        "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsf" | "vbe" | "jse" => "script".to_string(),
        "docm" | "xlsm" | "pptm" | "dotm" | "xltm" | "potm" => "document_with_macros".to_string(),
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => "archive".to_string(),
        "ini" | "cfg" | "conf" | "reg" => "configuration".to_string(),
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" => "document".to_string(),
        "txt" | "log" | "md" | "json" | "xml" | "yaml" | "yml" => "text".to_string(),
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "mp3" | "mp4" | "avi" | "mkv" => "media".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Analyze file path and properties for suspicious patterns
fn analyze_suspicious_patterns(file_path: &str, extension: &str, size_bytes: u64) -> (bool, Vec<String>) {
    let mut indicators = Vec::new();
    let path_lower = file_path.to_lowercase();

    // High-risk extensions
    let high_risk_extensions = [
        "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "wsf", "scr", "com",
        "pif", "application", "gadget", "msi", "msp", "hta", "cpl", "jar",
        "vbe", "jse", "ws", "wsh", "msc", "inf", "reg"
    ];

    if high_risk_extensions.contains(&extension) {
        indicators.push(format!("High-risk extension: .{}", extension));
    }

    // Suspicious locations
    let suspicious_locations = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
        "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\",
        "\\downloads\\", "\\desktop\\", "\\startup\\"
    ];

    for location in &suspicious_locations {
        if path_lower.contains(location) {
            indicators.push(format!("Suspicious location: {}", location.trim_matches('\\')));
            break;
        }
    }

    // Suspicious filename patterns
    let suspicious_patterns = [
        "crack", "keygen", "patch", "loader", "hack", "cheat", "bot",
        "miner", "crypter", "stealer", "backdoor", "rat", "trojan", "virus",
        "payload", "exploit", "shell", "inject", "dump", "bypass"
    ];

    for pattern in &suspicious_patterns {
        if path_lower.contains(pattern) {
            indicators.push(format!("Suspicious filename pattern: {}", pattern));
        }
    }

    // Scripting engine references
    let scripting_keywords = [
        "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "bitsadmin", "certutil"
    ];

    for keyword in &scripting_keywords {
        if path_lower.contains(keyword) {
            indicators.push(format!("Scripting reference: {}", keyword));
        }
    }

    // Suspicious file sizes
    if extension == "exe" && size_bytes < 10_000 {
        indicators.push("Unusually small executable (< 10KB)".to_string());
    }

    if extension == "dll" && size_bytes < 5_000 {
        indicators.push("Unusually small DLL (< 5KB)".to_string());
    }

    // Double extension trick
    if path_lower.contains(".pdf.exe") || path_lower.contains(".doc.exe") 
        || path_lower.contains(".jpg.exe") || path_lower.contains(".txt.exe") {
        indicators.push("Double extension detected (masquerading)".to_string());
    }

    let suspicious = !indicators.is_empty();
    (suspicious, indicators)
}

/// Calculate MD5 hash of file
fn calculate_md5_hash(path: &std::path::Path) -> Result<String, String> {
    let contents = fs::read(path)
        .map_err(|e| format!("Failed to read file for hashing: {}", e))?;
    
    let digest = md5::compute(&contents);
    
    Ok(format!("{:x}", digest))
}

// ============================================================================
// STAGES 2-4: INTEGRATION WITH EXISTING SCANNERS
// ============================================================================

use crate::registry_scanner;
use crate::service_scanner;
use crate::task_scanner;

/// Stage 2: Scan registry for references to target file
pub fn analyze_registry_stage(file_path: &str) -> Result<RegistryScanStage, String> {
    let scan_result = registry_scanner::scan_registry()
        .map_err(|e| format!("Registry scan failed: {}", e))?;

    let path_lower = file_path.to_lowercase();
    let mut related_entries = Vec::new();

for entry in &scan_result {
    let value_lower = entry.value_data.to_lowercase();  // ← value → value_data
    
    if value_lower.contains(&path_lower) {
        related_entries.push(format!("{}\\{}", entry.key_path, entry.value_name));  // ← path → key_path, name → value_name
        continue;
    }

    if let Some(filename) = std::path::Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str()) {
        if value_lower.contains(&filename.to_lowercase()) {
            related_entries.push(format!("{}\\{}", entry.key_path, entry.value_name));  // ← path → key_path, name → value_name
        }
    }
}

    Ok(RegistryScanStage {
        status: "success".to_string(),
        has_references: !related_entries.is_empty(),
        related_entries: related_entries.len(),
        registry_keys: related_entries,
    })
}

/// Stage 3: Scan services for dependencies on target file
pub fn analyze_service_stage(file_path: &str) -> Result<ServiceScanStage, String> {
    let scan_result = service_scanner::scan_services()
        .map_err(|e| format!("Service scan failed: {}", e))?;

    let path_lower = file_path.to_lowercase();
    let mut related_services = Vec::new();

  for service in &scan_result {
    let binary_path_lower = service.binary_path.to_lowercase();
    
    if binary_path_lower.contains(&path_lower) {
        related_services.push(service.service_name.clone());  // ← name → service_name
        continue;
    }

    if let Some(filename) = std::path::Path::new(file_path)
        .file_name()
        .and_then(|name| name.to_str()) {
        if binary_path_lower.contains(&filename.to_lowercase()) {
            related_services.push(service.service_name.clone());  // ← name → service_name
        }
    }
}

    Ok(ServiceScanStage {
        status: "success".to_string(),
        has_dependencies: !related_services.is_empty(),
        related_services: related_services.len(),
        service_names: related_services,
    })
}

/// Stage 4: Scan scheduled tasks for references to target file
pub fn analyze_task_stage(file_path: &str) -> Result<TaskScanStage, String> {
    let scan_result = task_scanner::scan_tasks()
        .map_err(|e| format!("Task scan failed: {}", e))?;

    let path_lower = file_path.to_lowercase();
    let mut related_tasks = Vec::new();

for task in &scan_result {
    // Search through all actions in the task
    let mut found = false;
    
    for action in &task.actions {
        // Check action path
        let action_path_lower = action.path.to_lowercase();
        
        if action_path_lower.contains(&path_lower) {
            found = true;
            break;
        }

        // Also check arguments (may contain file path)
        let arguments_lower = action.arguments.to_lowercase();
        if arguments_lower.contains(&path_lower) {
            found = true;
            break;
        }

        // Check for filename only
        if let Some(filename) = std::path::Path::new(file_path)
            .file_name()
            .and_then(|name| name.to_str()) {
            let filename_lower = filename.to_lowercase();
            if action_path_lower.contains(&filename_lower) || arguments_lower.contains(&filename_lower) {
                found = true;
                break;
            }
        }
    }
    
    if found {
        related_tasks.push(task.task_name.clone());
    }
}
    Ok(TaskScanStage {
        status: "success".to_string(),
        has_references: !related_tasks.is_empty(),
        related_tasks: related_tasks.len(),
        task_names: related_tasks,
    })
}

// ============================================================================
// MAIN DEEP ANALYSIS FUNCTION (ALL 4 STAGES)
// ============================================================================

/// Perform complete deep analysis - all 4 stages
pub fn perform_deep_analysis(file_path: &str) -> Result<DeepAnalysisResult, String> {
    let analysis_id = generate_analysis_id();
    let analyzed_at = chrono::Utc::now().to_rfc3339();

    println!("🔍 Stage 1: Analyzing file...");
    let file_stage = analyze_file_stage(file_path)?;

    println!("🔍 Stage 2: Scanning registry...");
    let registry_stage = analyze_registry_stage(file_path)?;

    println!("🔍 Stage 3: Scanning services...");
    let service_stage = analyze_service_stage(file_path)?;

    println!("🔍 Stage 4: Scanning tasks...");
    let task_stage = analyze_task_stage(file_path)?;

    let (risk_score, threat_level) = calculate_risk_score(
        &file_stage,
        &registry_stage,
        &service_stage,
        &task_stage,
    );

    let recommendations = generate_recommendations(
        &threat_level,
        &file_stage,
        &registry_stage,
        &service_stage,
        &task_stage,
    );

    println!("✅ Analysis complete! Threat Level: {} | Risk Score: {}", threat_level, risk_score);

    Ok(DeepAnalysisResult {
        analysis_id,
        target_path: file_path.to_string(),
        analyzed_at,
        stages: AnalysisStages {
            file_analysis: file_stage,
            registry_scan: registry_stage,
            service_scan: service_stage,
            task_scan: task_stage,
        },
        threat_level,
        risk_score,
        recommendations,
    })
}

// ============================================================================
// COMPLETE REMOVAL + BACKUP SYSTEM
// ============================================================================


use std::path::Path;

/// Perform complete removal with backup
pub fn perform_complete_removal(analysis: &DeepAnalysisResult) -> Result<RemovalResult, String> {
    // Create backup first
    println!("💾 Creating backup...");
    let backup_file = create_backup(analysis)?;
    println!("✅ Backup created: {}", backup_file);

    let mut removed_items = RemovedItems {
        file_removed: false,
        registry_entries_removed: 0,
        services_removed: 0,
        tasks_removed: 0,
    };

    // Step 1: Remove scheduled tasks (do first, as they might try to recreate file)
    if analysis.stages.task_scan.has_references {
        println!("🗑️ Removing scheduled tasks...");
        let tasks_removed = remove_scheduled_tasks(&analysis.stages.task_scan)?;
        removed_items.tasks_removed = tasks_removed;
        println!("✅ Removed {} tasks", tasks_removed);
    }

    // Step 2: Stop and remove services (do second, as they might have file locked)
    if analysis.stages.service_scan.has_dependencies {
        println!("🗑️ Stopping and removing services...");
        let services_removed = remove_services(&analysis.stages.service_scan)?;
        removed_items.services_removed = services_removed;
        println!("✅ Removed {} services", services_removed);
    }

    // Step 3: Remove registry entries (do third, so nothing can recreate file)
    if analysis.stages.registry_scan.has_references {
        println!("🗑️ Cleaning registry entries...");
        let registry_removed = remove_registry_entries(&analysis.stages.registry_scan)?;
        removed_items.registry_entries_removed = registry_removed;
        println!("✅ Cleaned {} registry entries", registry_removed);
    }

    // Step 4: Remove the file itself (do last)
    println!("🗑️ Removing target file...");
    let file_removed = remove_file(&analysis.target_path)?;
    removed_items.file_removed = file_removed;
    
    if file_removed {
        println!("✅ File removed successfully");
    } else {
        println!("⚠️ File could not be removed (may be locked or require elevated privileges)");
    }

    let message = format!(
        "Complete removal finished. Removed: {} file, {} registry entries, {} services, {} tasks",
        if removed_items.file_removed { "1" } else { "0" },
        removed_items.registry_entries_removed,
        removed_items.services_removed,
        removed_items.tasks_removed
    );

    Ok(RemovalResult {
        success: true,
        backup_file,
        removed_items,
        message,
    })
}

/// Create backup of analysis data
fn create_backup(analysis: &DeepAnalysisResult) -> Result<String, String> {
    // Ensure backup directory exists
    let backup_dir = get_backup_dir();
    fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("Failed to create backup directory: {}", e))?;

    // Generate backup filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("deep_quarantine_backup_{}.json", timestamp);
    let backup_path = backup_dir.join(&filename);

    // Create backup entry
    let backup = DeepQuarantineBackup {
        filename: filename.clone(),
        filepath: backup_path.to_string_lossy().to_string(),
        analysis_id: analysis.analysis_id.clone(),
        target_path: analysis.target_path.clone(),
        threat_level: analysis.threat_level.clone(),
        risk_score: analysis.risk_score,
        backed_up_at: chrono::Utc::now().to_rfc3339(),
        analysis_data: analysis.clone(),
    };

    // Write backup to JSON file
    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| format!("Failed to serialize backup: {}", e))?;
    
    fs::write(&backup_path, json)
        .map_err(|e| format!("Failed to write backup file: {}", e))?;

    Ok(backup_path.to_string_lossy().to_string())
}

/// Remove the target file
fn remove_file(file_path: &str) -> Result<bool, String> {
    let path = Path::new(file_path);
    
    if !path.exists() {
        return Ok(false); // File already removed or doesn't exist
    }

    match fs::remove_file(path) {
        Ok(_) => Ok(true),
        Err(e) => {
            // File might be locked or require admin privileges
            eprintln!("⚠️ Could not remove file: {}", e);
            Ok(false)
        }
    }
}

/// Remove registry entries using PowerShell
fn remove_registry_entries(registry_stage: &RegistryScanStage) -> Result<usize, String> {
    if registry_stage.registry_keys.is_empty() {
        return Ok(0);
    }

    let mut removed_count = 0;

    for registry_key in &registry_stage.registry_keys {
        // Parse registry key path (format: "HKLM\Path\ValueName")
        let parts: Vec<&str> = registry_key.rsplitn(2, '\\').collect();
        if parts.len() != 2 {
            eprintln!("⚠️ Invalid registry key format: {}", registry_key);
            continue;
        }

        let value_name = parts[0];
        let key_path = parts[1];

        // Remove registry value using PowerShell
        let ps_script = format!(
            "Remove-ItemProperty -Path 'Registry::{}' -Name '{}' -ErrorAction SilentlyContinue",
            key_path, value_name
        );

        match std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", &ps_script])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    removed_count += 1;
                } else {
                    eprintln!("⚠️ Failed to remove registry entry: {}", registry_key);
                }
            }
            Err(e) => {
                eprintln!("⚠️ PowerShell error: {}", e);
            }
        }
    }

    Ok(removed_count)
}

/// Stop and remove services using PowerShell
fn remove_services(service_stage: &ServiceScanStage) -> Result<usize, String> {
    if service_stage.service_names.is_empty() {
        return Ok(0);
    }

    let mut removed_count = 0;

    for service_name in &service_stage.service_names {
        // Stop the service first
        let stop_script = format!(
            "Stop-Service -Name '{}' -Force -ErrorAction SilentlyContinue",
            service_name
        );

        let _ = std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", &stop_script])
            .output();

        // Delete the service
        let delete_script = format!(
            "sc.exe delete '{}'",
            service_name
        );

        match std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", &delete_script])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    removed_count += 1;
                } else {
                    eprintln!("⚠️ Failed to remove service: {}", service_name);
                }
            }
            Err(e) => {
                eprintln!("⚠️ PowerShell error: {}", e);
            }
        }
    }

    Ok(removed_count)
}

/// Remove scheduled tasks using PowerShell
fn remove_scheduled_tasks(task_stage: &TaskScanStage) -> Result<usize, String> {
    if task_stage.task_names.is_empty() {
        return Ok(0);
    }

    let mut removed_count = 0;

    for task_name in &task_stage.task_names {
        let ps_script = format!(
            "Unregister-ScheduledTask -TaskName '{}' -Confirm:$false -ErrorAction SilentlyContinue",
            task_name
        );

        match std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", &ps_script])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    removed_count += 1;
                } else {
                    eprintln!("⚠️ Failed to remove task: {}", task_name);
                }
            }
            Err(e) => {
                eprintln!("⚠️ PowerShell error: {}", e);
            }
        }
    }

    Ok(removed_count)
}

/// List all backups
pub fn list_backups() -> Result<BackupList, String> {
    let backup_dir = get_backup_dir();
    
    if !backup_dir.exists() {
        return Ok(BackupList {
            backups: Vec::new(),
        });
    }

    let mut backups = Vec::new();

    let entries = fs::read_dir(&backup_dir)
        .map_err(|e| format!("Failed to read backup directory: {}", e))?;

    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            
            // Only process .json files
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            // Read and parse backup file
            if let Ok(contents) = fs::read_to_string(&path) {
                if let Ok(backup) = serde_json::from_str::<DeepQuarantineBackup>(&contents) {
                    backups.push(backup);
                }
            }
        }
    }

    // Sort by date (newest first)
    backups.sort_by(|a, b| b.backed_up_at.cmp(&a.backed_up_at));

    Ok(BackupList { backups })
}

#[cfg(test)]
mod removal_tests {
    use super::*;

    #[test]
    fn test_backup_directory_creation() {
        let backup_dir = get_backup_dir();
        assert!(backup_dir.to_string_lossy().contains("CyberGuardian"));
        assert!(backup_dir.to_string_lossy().contains("deep_quarantine_backups"));
    }

    #[test]
    fn test_list_backups_empty() {
        // This will pass even if directory doesn't exist
        let result = list_backups();
        assert!(result.is_ok());
    }
}