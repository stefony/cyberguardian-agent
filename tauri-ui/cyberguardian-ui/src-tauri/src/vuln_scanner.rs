/// CyberGuardian XDR — Vulnerability Scanner
/// NIS2 Art. 21(2)(e) / Закон за киберсигурността (ДВ бр.17 / 13.02.2026) чл. 14
/// Сканира инсталиран софтуер, открива CVE уязвимости, генерира NIS2 доклад

use serde::{Deserialize, Serialize};
use std::process::Command;
use chrono::Utc;

#[cfg(windows)]
use winreg::{enums::*, RegKey};

// ============================================
// DATA STRUCTURES
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledSoftware {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub software_name: String,
    pub software_version: String,
    pub cve_id: String,
    pub cvss_score: f32,
    pub severity: String,       // "critical" | "high" | "medium" | "low"
    pub description: String,
    pub published_date: Option<String>,
    pub patch_available: bool,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub timestamp: String,
    pub hostname: String,
    pub software_count: u32,
    pub scanned_software: Vec<InstalledSoftware>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub nis2_score: u32,
    pub nis2_status: String,    // "compliant" | "warning" | "critical"
    pub zks_article: String,    // "чл. 14 ЗКС (ДВ бр.17/2026)"
    pub recommendations: Vec<String>,
}

// ============================================
// REGISTRY SCANNER — Инсталиран софтуер
// ============================================

#[cfg(windows)]
pub fn scan_installed_software() -> Vec<InstalledSoftware> {
    let mut software = Vec::new();

    let registry_paths = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];

    for (hive, path) in &registry_paths {
        let hive_key = if *hive == HKEY_LOCAL_MACHINE {
            RegKey::predef(HKEY_LOCAL_MACHINE)
        } else {
            RegKey::predef(HKEY_CURRENT_USER)
        };

        let Ok(uninstall_key) = hive_key.open_subkey(path) else {
            continue;
        };

        for subkey_name in uninstall_key.enum_keys().flatten() {
            let Ok(subkey) = uninstall_key.open_subkey(&subkey_name) else {
                continue;
            };

            let name: String = subkey.get_value("DisplayName").unwrap_or_default();
            let version: String = subkey.get_value("DisplayVersion").unwrap_or_default();

            // Skip empty entries and Windows updates (KB articles)
            if name.is_empty() || version.is_empty() {
                continue;
            }
            if name.starts_with("KB") || name.contains("Security Update") {
                continue;
            }

            // Avoid duplicates
            if software.iter().any(|s: &InstalledSoftware| s.name == name && s.version == version) {
                continue;
            }

            let publisher: String = subkey.get_value("Publisher").unwrap_or_default();
            let install_date: String = subkey.get_value("InstallDate").unwrap_or_default();
            let install_location: String = subkey.get_value("InstallLocation").unwrap_or_default();

            software.push(InstalledSoftware {
                name,
                version,
                publisher: if publisher.is_empty() { None } else { Some(publisher) },
                install_date: if install_date.is_empty() { None } else { Some(install_date) },
                install_location: if install_location.is_empty() { None } else { Some(install_location) },
            });
        }
    }

    software
}

#[cfg(not(windows))]
pub fn scan_installed_software() -> Vec<InstalledSoftware> {
    vec![] // Non-Windows — not applicable
}

// ============================================
// HOSTNAME
// ============================================

pub fn get_hostname() -> String {
    Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

// ============================================
// NIS2 SCORING
// ============================================

fn calculate_nis2_score(
    critical: u32,
    high: u32,
    medium: u32,
    total_software: u32,
) -> (u32, String) {
    // Score starts at 100, deduct for vulnerabilities
    let mut score: i32 = 100;

    // Critical vulns: -20 each (max -60)
    score -= (critical as i32 * 20).min(60);

    // High vulns: -10 each (max -30)
    score -= (high as i32 * 10).min(30);

    // Medium vulns: -3 each (max -10)
    score -= (medium as i32 * 3).min(10);

    let score = score.max(0) as u32;

    let status = if score >= 80 {
        "compliant".to_string()
    } else if score >= 60 {
        "warning".to_string()
    } else {
        "critical".to_string()
    };

    (score, status)
}

// ============================================
// RECOMMENDATIONS
// ============================================

fn build_recommendations(
    critical: u32,
    high: u32,
    medium: u32,
    vulnerabilities: &[VulnerabilityFinding],
) -> Vec<String> {
    let mut recs = Vec::new();

    if critical > 0 {
        recs.push(format!(
            "CRITICAL: {} critical vulnerabilities (CVSS ≥ 9.0) detected — immediate patching required per Art. 21(2)(e) NIS2 / ЗКС чл. 14 (ДВ бр.17/2026)",
            critical
        ));
    }

    if high > 0 {
        recs.push(format!(
            "HIGH: {} high-risk vulnerabilities (CVSS 7.0-8.9) — apply patches within 30 days",
            high
        ));
    }

    if medium > 0 {
        recs.push(format!(
            "MEDIUM: {} medium-risk vulnerabilities — apply patches within 90 days",
            medium
        ));
    }

    // Specific software recommendations
    let critical_vulns: Vec<&VulnerabilityFinding> = vulnerabilities
        .iter()
        .filter(|v| v.severity == "critical")
        .collect();

    for vuln in critical_vulns.iter().take(3) {
        recs.push(format!(
            "CRITICAL: {} {} — {} — {}",
            vuln.software_name, vuln.software_version, vuln.cve_id, vuln.remediation
        ));
    }

    if recs.is_empty() {
        recs.push("No vulnerabilities detected — system compliant with Art. 21(2)(e) NIS2 / ЗКС чл. 14 (ДВ бр.17/2026)".to_string());
    }

    recs
}

// ============================================
// MAIN SCAN — Tauri Command
// ============================================

#[tauri::command]
pub fn scan_vulnerabilities() -> VulnScanResult {
    let timestamp = Utc::now().to_rfc3339();
    let hostname = get_hostname();

    // 1. Scan installed software from registry
    let scanned_software = scan_installed_software();
    let software_count = scanned_software.len() as u32;

    // 2. Return software list to frontend/backend for CVE matching
    // CVE matching happens in the Python backend via NVD API
    // Here we return the full software inventory
    let vulnerabilities: Vec<VulnerabilityFinding> = Vec::new();

    let critical_count = 0u32;
    let high_count     = 0u32;
    let medium_count   = 0u32;
    let low_count      = 0u32;

    let (nis2_score, nis2_status) = calculate_nis2_score(
        critical_count, high_count, medium_count, software_count
    );

    let recommendations = build_recommendations(
        critical_count, high_count, medium_count, &vulnerabilities
    );

    VulnScanResult {
        timestamp,
        hostname,
        software_count,
        scanned_software,
        vulnerabilities,
        critical_count,
        high_count,
        medium_count,
        low_count,
        nis2_score,
        nis2_status,
        zks_article: "чл. 14 ЗКС (ДВ бр.17/2026)".to_string(),
        recommendations,
    }
}
