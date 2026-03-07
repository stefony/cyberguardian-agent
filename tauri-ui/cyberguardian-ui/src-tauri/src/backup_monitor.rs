/// CyberGuardian XDR — Backup Security Monitor
/// NIS2 Art. 21(2)(c) — Business Continuity & Backup Management
/// Detects backup solutions, VSS status, ransomware backup attacks

use serde::{Deserialize, Serialize};
use std::process::Command;
use chrono::Utc;

// ============================================
// DATA STRUCTURES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSolution {
    pub name: String,
    pub vendor: String,
    pub detection_method: String, // "service" | "process" | "registry" | "task"
    pub status: String,           // "running" | "stopped" | "installed"
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssStatus {
    pub service_running: bool,
    pub snapshot_count: u32,
    pub last_snapshot: Option<String>,
    pub protection_status: String, // "protected" | "at_risk" | "unknown"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEvent {
    pub timestamp: String,
    pub event_id: u32,
    pub source: String,
    pub message: String,
    pub event_type: String, // "success" | "failure" | "warning" | "tamper"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareBackupThreat {
    pub detected: bool,
    pub threat_type: String,
    pub command_detected: Option<String>,
    pub timestamp: Option<String>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupFreshness {
    pub last_backup_time: Option<String>,
    pub age_hours: Option<i64>,
    pub status: String,   // "fresh" | "stale" | "unknown"
    pub frequency: String, // "daily" | "weekly" | "unknown"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSecurityReport {
    pub timestamp: String,
    pub solutions: Vec<BackupSolution>,
    pub vss_status: VssStatus,
    pub freshness: BackupFreshness,
    pub recent_events: Vec<BackupEvent>,
    pub ransomware_threats: Vec<RansomwareBackupThreat>,
    pub nis2_score: u32,
    pub nis2_status: String,  // "compliant" | "warning" | "critical"
    pub compliance_details: Vec<ComplianceDetail>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceDetail {
    pub article: String,
    pub requirement: String,
    pub status: String,
    pub score: u32,
    pub finding: String,
}

// ============================================
// BACKUP SOLUTION DETECTION
// ============================================

/// Known backup software — service names, process names, registry keys
const BACKUP_SERVICES: &[(&str, &str, &str)] = &[
    ("WBENGINE",           "Windows Backup",         "Microsoft"),
    ("SDRSVC",             "Windows Backup",         "Microsoft"),
    ("VSS",                "Volume Shadow Copy",     "Microsoft"),
    ("VeeamAgentSvc",      "Veeam Agent",            "Veeam"),
    ("VeeamBackupSvc",     "Veeam Backup",           "Veeam"),
    ("AcronisManagedMachine", "Acronis",             "Acronis"),
    ("AcronisAgent",       "Acronis Agent",          "Acronis"),
    ("BackupExecAgentAccelerator", "Veritas Backup Exec", "Veritas"),
    ("BackupExecDeviceMediaService", "Veritas Backup Exec", "Veritas"),
    ("CvMountd",           "Commvault",              "Commvault"),
    ("GxCVD",              "Commvault",              "Commvault"),
    ("MSSQLSERVER",        "SQL Server (backup capable)", "Microsoft"),
    ("AhsayOBM",           "Ahsay Backup",           "Ahsay"),
    ("CoheritAgent",       "Cohesity Agent",         "Cohesity"),
    ("RubrikBackup",       "Rubrik Backup",          "Rubrik"),
];

const BACKUP_PROCESSES: &[(&str, &str, &str)] = &[
    ("wbengine.exe",       "Windows Backup Engine",  "Microsoft"),
    ("veeam.backup.agent.configurationservice.exe", "Veeam Agent", "Veeam"),
    ("VeeamAgent.exe",     "Veeam Agent",            "Veeam"),
    ("acronis_agent.exe",  "Acronis Agent",          "Acronis"),
    ("TrueImageService.exe", "Acronis True Image",   "Acronis"),
    ("BackupExec.exe",     "Veritas Backup Exec",    "Veritas"),
    ("cvd.exe",            "Commvault",              "Commvault"),
];

pub fn detect_backup_solutions() -> Vec<BackupSolution> {
    let mut solutions = Vec::new();

    // 1. Check services
    if let Ok(output) = Command::new("sc")
        .args(["query", "type=", "all", "state=", "all"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
        for (svc_name, display_name, vendor) in BACKUP_SERVICES {
            if text.contains(&svc_name.to_lowercase()) {
                let status = if text.contains(&format!("{}  \r\n        state", svc_name.to_lowercase())) {
                    "running"
                } else {
                    "installed"
                };
                solutions.push(BackupSolution {
                    name: display_name.to_string(),
                    vendor: vendor.to_string(),
                    detection_method: "service".to_string(),
                    status: status.to_string(),
                    version: None,
                });
            }
        }
    }

    // 2. Check running processes
    if let Ok(output) = Command::new("tasklist")
        .args(["/fo", "csv", "/nh"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
        for (proc_name, display_name, vendor) in BACKUP_PROCESSES {
            if text.contains(&proc_name.to_lowercase()) {
                // Avoid duplicates
                if !solutions.iter().any(|s| s.name == *display_name) {
                    solutions.push(BackupSolution {
                        name: display_name.to_string(),
                        vendor: vendor.to_string(),
                        detection_method: "process".to_string(),
                        status: "running".to_string(),
                        version: None,
                    });
                }
            }
        }
    }

    // 3. Check scheduled tasks for backup tasks
    if let Ok(output) = Command::new("schtasks")
        .args(["/query", "/fo", "csv", "/nh"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
        let backup_keywords = ["backup", "veeam", "acronis", "shadow", "wbadmin"];
        for keyword in &backup_keywords {
            if text.contains(keyword) {
                if !solutions.iter().any(|s| s.detection_method == "task" && s.name.to_lowercase().contains(keyword)) {
                    solutions.push(BackupSolution {
                        name: format!("Scheduled Backup Task ({})", keyword),
                        vendor: "Unknown".to_string(),
                        detection_method: "task".to_string(),
                        status: "scheduled".to_string(),
                        version: None,
                    });
                }
            }
        }
    }

    // 4. Check Windows Backup via wbadmin
    if let Ok(output) = Command::new("wbadmin")
        .args(["get", "versions"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if !text.contains("ERROR") && text.len() > 50 {
            if !solutions.iter().any(|s| s.name == "Windows Backup") {
                solutions.push(BackupSolution {
                    name: "Windows Backup".to_string(),
                    vendor: "Microsoft".to_string(),
                    detection_method: "wbadmin".to_string(),
                    status: "active".to_string(),
                    version: None,
                });
            }
        }
    }

    solutions
}

// ============================================
// VSS STATUS
// ============================================

pub fn get_vss_status() -> VssStatus {
    // Check VSS service
    let service_running = Command::new("sc")
        .args(["query", "VSS"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false);

    // Count VSS snapshots
    let snapshot_count = Command::new("vssadmin")
        .args(["list", "shadows"])
        .output()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            text.matches("Shadow Copy ID:").count() as u32
        })
        .unwrap_or(0);

    // Get last snapshot time
    let last_snapshot = Command::new("vssadmin")
        .args(["list", "shadows"])
        .output()
        .ok()
        .and_then(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            // Extract last "Creation Time:" line
            text.lines()
                .filter(|l| l.contains("Creation Time:"))
                .last()
                .map(|l| l.replace("   Creation Time:", "").trim().to_string())
        });

    let protection_status = if service_running && snapshot_count > 0 {
        "protected".to_string()
    } else if service_running {
        "at_risk".to_string()
    } else {
        "critical".to_string()
    };

    VssStatus {
        service_running,
        snapshot_count,
        last_snapshot,
        protection_status,
    }
}

// ============================================
// BACKUP FRESHNESS
// ============================================

pub fn get_backup_freshness() -> BackupFreshness {
    // Try wbadmin to get last backup time
    let wbadmin_output = Command::new("wbadmin")
        .args(["get", "versions"])
        .output()
        .ok();

    if let Some(output) = wbadmin_output {
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        // Find last "Backup Time:" line
        if let Some(line) = text.lines()
            .filter(|l| l.contains("Backup Time:") || l.contains("Backup time:"))
            .last()
        {
            let time_str = line
                .replace("Backup Time:", "")
                .replace("Backup time:", "")
                .trim()
                .to_string();

            // Try to parse and calculate age
            // Windows format: "3/6/2026 2:00 AM"
            let age_hours = parse_backup_age_hours(&time_str);

            let status = match age_hours {
                Some(h) if h <= 24 => "fresh".to_string(),
                Some(h) if h <= 168 => "stale".to_string(), // 7 days
                Some(_) => "critical".to_string(),
                None => "unknown".to_string(),
            };

            let frequency = if age_hours.map_or(false, |h| h <= 25) {
                "daily".to_string()
            } else if age_hours.map_or(false, |h| h <= 169) {
                "weekly".to_string()
            } else {
                "unknown".to_string()
            };

            return BackupFreshness {
                last_backup_time: Some(time_str),
                age_hours,
                status,
                frequency,
            };
        }
    }

    // Fallback: check Event Log for backup success events
    let event_output = Command::new("wevtutil")
        .args([
            "qe", "Microsoft-Windows-Backup",
            "/c:1", "/rd:true", "/f:text",
        ])
        .output()
        .ok();

    if let Some(output) = event_output {
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        if text.contains("4") && text.len() > 50 {
            return BackupFreshness {
                last_backup_time: Some("Recent (from Event Log)".to_string()),
                age_hours: None,
                status: "unknown".to_string(),
                frequency: "unknown".to_string(),
            };
        }
    }

    BackupFreshness {
        last_backup_time: None,
        age_hours: None,
        status: "unknown".to_string(),
        frequency: "unknown".to_string(),
    }
}

fn parse_backup_age_hours(time_str: &str) -> Option<i64> {
    // Try common Windows date formats
    // Just return None if we can't parse — better than wrong data
    let _ = time_str;
    None // Will be improved with proper date parsing
}

// ============================================
// RANSOMWARE BACKUP THREAT DETECTION
// ============================================

/// Commands used by ransomware to destroy backups
const RANSOMWARE_BACKUP_CMDS: &[(&str, &str)] = &[
    ("vssadmin delete shadows",       "VSS Shadow Copy Deletion"),
    ("vssadmin resize shadowstorage", "VSS Storage Resize"),
    ("wmic shadowcopy delete",        "WMI Shadow Copy Deletion"),
    ("bcdedit /set recoveryenabled no", "Boot Recovery Disabled"),
    ("bcdedit /set bootstatuspolicy", "Boot Status Policy Modified"),
    ("wbadmin delete catalog",        "Windows Backup Catalog Deletion"),
    ("wbadmin delete systemstatebackup", "System State Backup Deletion"),
    ("diskshadow /s",                 "DiskShadow Script Execution"),
    ("net stop vss",                  "VSS Service Stopped"),
    ("net stop swprv",                "Shadow Copy Provider Stopped"),
    ("taskkill /f /im wbengine",      "Windows Backup Engine Killed"),
];

pub fn detect_ransomware_backup_threats() -> Vec<RansomwareBackupThreat> {
    let mut threats = Vec::new();

    // Check recent PowerShell/CMD event logs for ransomware backup commands
    // Event ID 4688 — Process Creation (requires audit policy)
    let ps_output = Command::new("wevtutil")
        .args([
            "qe", "Security",
            "/q:*[System[(EventID=4688)]]",
            "/c:100", "/rd:true", "/f:text",
        ])
        .output()
        .ok();

    if let Some(output) = ps_output {
        let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
        for (cmd, threat_type) in RANSOMWARE_BACKUP_CMDS {
            if text.contains(&cmd.to_lowercase()) {
                threats.push(RansomwareBackupThreat {
                    detected: true,
                    threat_type: threat_type.to_string(),
                    command_detected: Some(cmd.to_string()),
                    timestamp: Some(Utc::now().to_rfc3339()),
                    severity: "critical".to_string(),
                });
            }
        }
    }

    // Also check PowerShell Script Block Logging (Event ID 4104)
    let ps_block_output = Command::new("wevtutil")
        .args([
            "qe", "Microsoft-Windows-PowerShell/Operational",
            "/q:*[System[(EventID=4104)]]",
            "/c:50", "/rd:true", "/f:text",
        ])
        .output()
        .ok();

    if let Some(output) = ps_block_output {
        let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
        for (cmd, threat_type) in RANSOMWARE_BACKUP_CMDS {
            if text.contains(&cmd.to_lowercase()) {
                if !threats.iter().any(|t: &RansomwareBackupThreat| t.threat_type == *threat_type) {
                    threats.push(RansomwareBackupThreat {
                        detected: true,
                        threat_type: threat_type.to_string(),
                        command_detected: Some(cmd.to_string()),
                        timestamp: Some(Utc::now().to_rfc3339()),
                        severity: "critical".to_string(),
                    });
                }
            }
        }
    }

    threats
}

// ============================================
// RECENT BACKUP EVENTS
// ============================================

pub fn get_recent_backup_events() -> Vec<BackupEvent> {
    let mut events = Vec::new();

    // Windows Backup event log
    let output = Command::new("wevtutil")
        .args([
            "qe", "Microsoft-Windows-Backup",
            "/c:20", "/rd:true", "/f:text",
        ])
        .output()
        .ok();

    if let Some(output) = output {
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        let mut current_event = BackupEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_id: 0,
            source: "Windows Backup".to_string(),
            message: String::new(),
            event_type: "info".to_string(),
        };

        for line in text.lines() {
            if line.contains("Date:") || line.contains("TimeCreated") {
                current_event.timestamp = line
                    .replace("  Date:", "")
                    .replace("TimeCreated:", "")
                    .trim()
                    .to_string();
            }
            if line.contains("Event ID:") || line.contains("Id:") {
                if let Some(id_str) = line.split(':').nth(1) {
                    current_event.event_id = id_str.trim().parse().unwrap_or(0);
                }
                // Classify event type by ID
                current_event.event_type = match current_event.event_id {
                    4 | 14 | 18 | 25 => "success".to_string(),
                    5 | 9 | 17 | 49  => "failure".to_string(),
                    19 | 20          => "warning".to_string(),
                    _                => "info".to_string(),
                };
            }
            if line.contains("Message:") || (line.trim().len() > 20 && current_event.message.is_empty()) {
                current_event.message = line.replace("Message:", "").trim().to_string();
                if !current_event.message.is_empty() && current_event.event_id > 0 {
                    events.push(current_event.clone());
                    current_event = BackupEvent {
                        timestamp: Utc::now().to_rfc3339(),
                        event_id: 0,
                        source: "Windows Backup".to_string(),
                        message: String::new(),
                        event_type: "info".to_string(),
                    };
                }
            }
        }
    }

    // VSS events
    let vss_output = Command::new("wevtutil")
        .args([
            "qe", "Application",
            "/q:*[System[Provider[@Name='VSS']]]",
            "/c:10", "/rd:true", "/f:text",
        ])
        .output()
        .ok();

    if let Some(output) = vss_output {
        let text = String::from_utf8_lossy(&output.stdout).to_string();
        if text.len() > 50 {
            events.push(BackupEvent {
                timestamp: Utc::now().to_rfc3339(),
                event_id: 0,
                source: "VSS".to_string(),
                message: "VSS events detected in Application log".to_string(),
                event_type: "info".to_string(),
            });
        }
    }

    events
}

// ============================================
// NIS2 SCORING
// ============================================

fn calculate_nis2_score(
    solutions: &[BackupSolution],
    vss: &VssStatus,
    freshness: &BackupFreshness,
    threats: &[RansomwareBackupThreat],
) -> (u32, String, Vec<ComplianceDetail>) {
    let mut details = Vec::new();
    let mut total = 0u32;

    // 1. Backup solution exists (30 points)
    let backup_score = if solutions.is_empty() { 0 }
        else if solutions.iter().any(|s| s.status == "running" || s.status == "active") { 30 }
        else { 15 };
    total += backup_score;
    details.push(ComplianceDetail {
        article: "Art. 21(2)(c)".to_string(),
        requirement: "Backup solution installed and active".to_string(),
        status: if backup_score == 30 { "compliant".to_string() }
                else if backup_score > 0 { "warning".to_string() }
                else { "critical".to_string() },
        score: backup_score,
        finding: if solutions.is_empty() {
            "No backup solution detected".to_string()
        } else {
            format!("{} solution(s) detected: {}",
                solutions.len(),
                solutions.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", "))
        },
    });

    // 2. VSS protection (25 points)
    let vss_score = if vss.service_running && vss.snapshot_count > 0 { 25 }
        else if vss.service_running { 12 }
        else { 0 };
    total += vss_score;
    details.push(ComplianceDetail {
        article: "Art. 21(2)(c)".to_string(),
        requirement: "Volume Shadow Copy protection active".to_string(),
        status: if vss_score == 25 { "compliant".to_string() }
                else if vss_score > 0 { "warning".to_string() }
                else { "critical".to_string() },
        score: vss_score,
        finding: format!("VSS service: {} | Snapshots: {}",
            if vss.service_running { "Running" } else { "Stopped" },
            vss.snapshot_count),
    });

    // 3. Backup freshness (25 points)
    let fresh_score = match freshness.status.as_str() {
        "fresh"   => 25,
        "stale"   => 10,
        "unknown" => 5,
        _         => 0,
    };
    total += fresh_score;
    details.push(ComplianceDetail {
        article: "Art. 21(2)(c)".to_string(),
        requirement: "Recent backup available (max 24h for critical systems)".to_string(),
        status: if fresh_score >= 25 { "compliant".to_string() }
                else if fresh_score > 0 { "warning".to_string() }
                else { "critical".to_string() },
        score: fresh_score,
        finding: freshness.last_backup_time.clone()
            .unwrap_or_else(|| "No recent backup found".to_string()),
    });

    // 4. No ransomware backup tampering (20 points)
    let tamper_score = if threats.is_empty() { 20 } else { 0 };
    total += tamper_score;
    details.push(ComplianceDetail {
        article: "Art. 21(2)(c)".to_string(),
        requirement: "No ransomware backup tampering detected".to_string(),
        status: if tamper_score == 20 { "compliant".to_string() }
                else { "critical".to_string() },
        score: tamper_score,
        finding: if threats.is_empty() {
            "No backup tampering detected".to_string()
        } else {
            format!("{} ransomware backup threat(s) detected!", threats.len())
        },
    });

    let status = if total >= 80 { "compliant".to_string() }
        else if total >= 60 { "warning".to_string() }
        else { "critical".to_string() };

    (total, status, details)
}

// ============================================
// RECOMMENDATIONS
// ============================================

fn build_recommendations(
    solutions: &[BackupSolution],
    vss: &VssStatus,
    freshness: &BackupFreshness,
    threats: &[RansomwareBackupThreat],
) -> Vec<String> {
    let mut recs = Vec::new();

    if solutions.is_empty() {
        recs.push("CRITICAL: Install a backup solution immediately (Veeam, Acronis, or Windows Backup) — required by NIS2 Art. 21(2)(c)".to_string());
    }

    if !vss.service_running {
        recs.push("CRITICAL: Enable Volume Shadow Copy Service — essential for ransomware recovery".to_string());
    } else if vss.snapshot_count == 0 {
        recs.push("HIGH: Configure VSS to create regular shadow copies for ransomware protection".to_string());
    }

    if freshness.status == "unknown" || freshness.last_backup_time.is_none() {
        recs.push("HIGH: Configure automated daily backups — NIS2 requires verifiable backup schedule".to_string());
    } else if freshness.status == "stale" {
        recs.push("MEDIUM: Last backup is older than 24 hours — increase backup frequency".to_string());
    }

    if !threats.is_empty() {
        recs.push("CRITICAL: Ransomware backup tampering detected — isolate system immediately and restore from clean backup".to_string());
    }

    if recs.is_empty() {
        recs.push("Backup posture is good — maintain current backup schedule and test recovery procedures quarterly".to_string());
    }

    recs
}

// ============================================
// MAIN SCAN FUNCTION (Tauri command)
// ============================================

#[tauri::command]
pub fn scan_backup_security() -> BackupSecurityReport {
    let timestamp = Utc::now().to_rfc3339();

    let solutions  = detect_backup_solutions();
    let vss        = get_vss_status();
    let freshness  = get_backup_freshness();
    let events     = get_recent_backup_events();
    let threats    = detect_ransomware_backup_threats();

    let (nis2_score, nis2_status, compliance_details) =
        calculate_nis2_score(&solutions, &vss, &freshness, &threats);

    let recommendations = build_recommendations(&solutions, &vss, &freshness, &threats);

    BackupSecurityReport {
        timestamp,
        solutions,
        vss_status: vss,
        freshness,
        recent_events: events,
        ransomware_threats: threats,
        nis2_score,
        nis2_status,
        compliance_details,
        recommendations,
    }
}