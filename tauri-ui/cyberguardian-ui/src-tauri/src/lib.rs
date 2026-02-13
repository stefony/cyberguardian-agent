mod file_watcher;
mod process_protection;
mod registry_scanner;
mod service_scanner;
mod task_scanner;
mod deep_quarantine;

#[cfg(windows)]
mod windows_service;
mod process_monitor;

use tauri::{
    Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
};

use registry_scanner::{scan_registry, calculate_statistics};
use service_scanner::{scan_services, calculate_statistics as calculate_service_stats};
use task_scanner::{scan_tasks, calculate_statistics as calculate_task_stats};


#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}
#[tauri::command]
fn start_file_protection(
    paths: Vec<String>,
    backend_url: String,
    token: String
) -> Result<String, String> {
    println!("🛡️ Starting file protection for: {:?}", paths);
    println!("🔗 Backend URL: {}", backend_url);
    println!("🔑 Token length: {}", token.len());
    
    std::env::set_var("RAILWAY_BACKEND_URL", backend_url);
    std::env::set_var("AUTH_TOKEN", token);
    
    match file_watcher::start_watching(paths) {
        Ok(_) => Ok("File protection started".to_string()),
        Err(e) => Err(format!("Failed to start protection: {}", e)),
    }
}

#[tauri::command]
async fn create_quarantine_record(
    file_path: String,
    threat_score: f64,
    _threat_level: String,
    _detection_method: String,
    _reason: String,
) -> Result<String, String> {
    println!("📝 Tauri command called: create_quarantine_record");
    println!("   File: {}", file_path);
    println!("   Score: {}", threat_score);
    Ok("Command received by Rust".to_string())
}

#[tauri::command]
async fn scan_windows_registry() -> Result<serde_json::Value, String> {
    match scan_registry() {
        Ok(entries) => {
            let stats = calculate_statistics(&entries);
            Ok(serde_json::json!({
                "entries": entries,
                "statistics": stats,
                "scanned_at": chrono::Utc::now().to_rfc3339()
            }))
        }
        Err(e) => Err(format!("Registry scan failed: {}", e))
    }
}

#[tauri::command]
async fn scan_windows_services() -> Result<serde_json::Value, String> {
    match scan_services() {
        Ok(services) => {
            let stats = calculate_service_stats(&services);
            Ok(serde_json::json!({
                "services": services,
                "statistics": stats,
                "scanned_at": chrono::Utc::now().to_rfc3339()
            }))
        }
        Err(e) => Err(format!("Service scan failed: {}", e))
    }
}

#[tauri::command]
async fn scan_windows_tasks() -> Result<serde_json::Value, String> {
    match scan_tasks() {
        Ok(tasks) => {
            let stats = calculate_task_stats(&tasks);
            Ok(serde_json::json!({
                "tasks": tasks,
                "statistics": stats,
                "scanned_at": chrono::Utc::now().to_rfc3339()
            }))
        }
        Err(e) => Err(format!("Task scan failed: {}", e))
    }
}

#[tauri::command]
async fn start_local_scan(
    profile: String,
    backend_url: String,
    token: String,
) -> Result<serde_json::Value, String> {
    use std::time::Instant;
    use std::path::Path;
    use std::fs;
    
    println!("🔍 Starting LOCAL {} scan on Windows", profile);
    
    let start_time = Instant::now();
    let mut files_scanned = 0;
    let mut threats_found = 0;
    
    let (max_files, scan_paths, extensions, recursive): (usize, Vec<&str>, Vec<&str>, bool) = match profile.as_str() {
        "quick" => (
            100,
            vec![
                r"C:\Users\admin\Downloads",
                r"C:\Users\admin\AppData\Local\Temp",
                r"C:\Windows\Temp",
            ],
            vec![".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".js"],
            false
        ),
        "standard" => (
            1000,
            vec![
                r"C:\Users\admin\Downloads",
                r"C:\Users\admin\Documents",
                r"C:\Users\admin\Desktop",
                r"C:\Users\admin\AppData",
            ],
            vec![".exe", ".dll", ".bat", ".ps1", ".zip", ".rar", ".7z", ".jar"],
            true
        ),
        "deep" => (
            10000,
            vec![r"C:\"],
            vec!["*"],
            true
        ),
        _ => (100, vec![r"C:\Users\admin\Downloads"], vec![".exe", ".dll"], false),
    };
    
    println!("📁 Scanning {} paths (max {} files)", scan_paths.len(), max_files);
    
    for scan_path in &scan_paths {
        if files_scanned >= max_files {
            break;
        }
        
        let path = Path::new(scan_path);
        if !path.exists() {
            println!("⚠️ Path does not exist: {}", scan_path);
            continue;
        }
        
        println!("📂 Scanning: {}", scan_path);
        
        fn scan_directory(
            path: &Path,
            extensions: &Vec<&str>,
            recursive: bool,
            files_scanned: &mut usize,
            threats_found: &mut usize,
            max_files: usize,
        ) {
            if *files_scanned >= max_files {
                return;
            }
            
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries {
                    if *files_scanned >= max_files {
                        break;
                    }
                    
                    if let Ok(entry) = entry {
                        let file_path = entry.path();
                        
                        if file_path.is_file() {
                            let should_scan = extensions.contains(&"*") || 
                                file_path.extension()
                                    .and_then(|ext| ext.to_str())
                                    .map(|ext| {
                                        let ext_with_dot = format!(".{}", ext);
                                        extensions.contains(&ext_with_dot.as_str())
                                    })
                                    .unwrap_or(false);
                            
                            if should_scan {
                                *files_scanned += 1;
                                
                                if let Some(file_name) = file_path.file_name() {
                                    let name = file_name.to_string_lossy().to_lowercase();
                                    if name.contains("virus") || name.contains("malware") || 
                                       name.contains("trojan") || name.contains("hack") ||
                                       name.contains("ransom") || name.contains("keylog") {
                                        *threats_found += 1;
                                        println!("🚨 Potential threat: {:?}", file_path);
                                    }
                                }
                                
                                if *files_scanned % 100 == 0 {
                                    println!("   Progress: {} files scanned", files_scanned);
                                }
                            }
                        } else if file_path.is_dir() && recursive {
                            scan_directory(&file_path, extensions, recursive, files_scanned, threats_found, max_files);
                        }
                    }
                }
            }
        }
        
        scan_directory(path, &extensions, recursive, &mut files_scanned, &mut threats_found, max_files);
    }
    
    let duration = start_time.elapsed().as_secs();
    
    println!("✅ Scan completed: {} files, {} threats, {}s", 
             files_scanned, threats_found, duration);
    
    let client = reqwest::Client::new();
    let target_path = scan_paths.join("; ");
    
    let history_data = serde_json::json!({
        "schedule_id": null,
        "scan_type": profile,
        "target_path": target_path,
        "started_at": chrono::Utc::now().to_rfc3339(),
        "status": "completed",
        "files_scanned": files_scanned,
        "threats_found": threats_found,
        "duration_seconds": duration,
    });
    
    match client
        .post(format!("{}/api/scans/history", backend_url))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .json(&history_data)
        .send()
        .await
    {
        Ok(response) => {
            println!("✅ Results sent to backend: {}", response.status());
            Ok(serde_json::json!({
                "success": true,
                "files_scanned": files_scanned,
                "threats_found": threats_found,
                "duration": duration
            }))
        }
        Err(e) => {
            println!("❌ Failed to send results: {}", e);
            Err(format!("Failed to send results: {}", e))
        }
    }
}

// ============================================================================
// PROCESS PROTECTION COMMANDS
// ============================================================================

/// Initialize process protection
#[tauri::command]
fn init_tamper_protection() -> Result<String, String> {
    process_protection::init_protection()?;
    Ok("Process protection initialized".to_string())
}

/// Get protection status
#[tauri::command]
fn get_desktop_protection_status() -> Result<process_protection::ProtectionStatus, String> {
    Ok(process_protection::get_protection_status())
}

/// Enable maximum protection
#[tauri::command]
fn enable_desktop_max_protection() -> Result<String, String> {
    process_protection::enable_max_protection()?;
    Ok("Maximum protection enabled".to_string())
}

/// Disable protection
#[tauri::command]
fn disable_desktop_protection() -> Result<String, String> {
    process_protection::disable_protection()?;
    Ok("Protection disabled".to_string())
}

/// Check if running as admin
#[tauri::command]
fn check_admin_privileges() -> Result<bool, String> {
    Ok(process_protection::ProcessProtection::check_admin_privileges())
}

/// Enable anti-termination protection
#[tauri::command]
fn enable_anti_termination_desktop() -> Result<String, String> {
    process_protection::enable_anti_termination_only()?;
    Ok("Anti-termination protection enabled".to_string())
}

/// Enable self-healing watchdog
#[tauri::command]
fn enable_self_healing_desktop() -> Result<String, String> {
    process_protection::enable_self_healing_only()?;
    Ok("Self-healing watchdog enabled".to_string())
}

/// Install as Windows service
#[tauri::command]
fn install_service_desktop() -> Result<String, String> {
    process_protection::install_as_service()?;
    Ok("Service installation initiated".to_string())
}

// ============================================================================
// PROCESS MONITORING COMMANDS
// ============================================================================

/// Get all running processes from Windows
#[tauri::command]
fn get_windows_processes() -> Result<Vec<process_monitor::ProcessInfo>, String> {
    process_monitor::get_running_processes()
}

/// Get process monitoring statistics
#[tauri::command]
fn get_process_stats() -> Result<process_monitor::ProcessStats, String> {
    let processes = process_monitor::get_running_processes()?;
    Ok(process_monitor::get_process_statistics(&processes))
}

// ============================================================================
// SERVICE MANAGEMENT COMMANDS
// ============================================================================

/// Check if service is installed
#[tauri::command]
fn check_service_installed() -> Result<bool, String> {
    #[cfg(windows)]
    {
        Ok(crate::windows_service::is_service_installed())
    }
    #[cfg(not(windows))]
    Ok(false)
}

/// Check if service is running
#[tauri::command]
fn check_service_running() -> Result<bool, String> {
    #[cfg(windows)]
    {
        Ok(crate::windows_service::is_service_running())
    }
    #[cfg(not(windows))]
    Ok(false)
}

/// Get service status string
#[tauri::command]
fn get_service_status() -> Result<String, String> {
    #[cfg(windows)]
    {
        Ok(crate::windows_service::get_service_status())
    }
    #[cfg(not(windows))]
    Ok("Not Supported".to_string())
}

/// Start the Windows service
#[tauri::command]
fn start_service_command() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::windows_service::start_service()?;
        Ok("Service started successfully".to_string())
    }
    #[cfg(not(windows))]
    Err("Not supported on this platform".to_string())
}

/// Stop the Windows service
#[tauri::command]
fn stop_service_command() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::windows_service::stop_service()?;
        Ok("Service stopped successfully".to_string())
    }
    #[cfg(not(windows))]
    Err("Not supported on this platform".to_string())
}

/// Uninstall the Windows service
#[tauri::command]
fn uninstall_service_command() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::windows_service::uninstall_service()?;
        Ok("Service uninstalled successfully".to_string())
    }
    #[cfg(not(windows))]
    Err("Not supported on this platform".to_string())
}

// ============================================================================
// DEEP QUARANTINE COMMANDS
// ============================================================================

use crate::deep_quarantine::*;

/// Analyze file with all 4 stages
#[tauri::command]
async fn deep_quarantine_analyze(file_path: String) -> Result<DeepAnalysisResult, String> {
    println!("🔍 Starting deep analysis for: {}", file_path);
    
    match perform_deep_analysis(&file_path) {
        Ok(result) => {
            println!("✅ Deep analysis completed successfully");
            Ok(result)
        }
        Err(e) => {
            eprintln!("❌ Deep analysis failed: {}", e);
            Err(e)
        }
    }
}

/// Perform complete removal with backup
#[tauri::command]
async fn deep_quarantine_remove(analysis_data: DeepAnalysisResult) -> Result<RemovalResult, String> {
    println!("🗑️ Starting complete removal...");
    
    match perform_complete_removal(&analysis_data) {
        Ok(result) => {
            println!("✅ Complete removal finished successfully");
            Ok(result)
        }
        Err(e) => {
            eprintln!("❌ Removal failed: {}", e);
            Err(e)
        }
    }
}

/// List all Deep Quarantine backups
#[tauri::command]
async fn deep_quarantine_list_backups() -> Result<BackupList, String> {
    println!("📋 Listing Deep Quarantine backups...");
    
    match list_backups() {
        Ok(list) => {
            println!("✅ Found {} backups", list.backups.len());
            Ok(list)
        }
        Err(e) => {
            eprintln!("❌ Failed to list backups: {}", e);
            Err(e)
        }
    }
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .setup(|app| {
            println!("🔧 Setup starting...");

            let dashboard_item =
                MenuItem::with_id(app, "dashboard", "Open Dashboard", true, None::<&str>)?;
            let protection_item =
                MenuItem::with_id(app, "protection", "Protection: ON", true, None::<&str>)?;
            let settings_item =
                MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
            let devtools_item =
                MenuItem::with_id(app, "toggle_devtools", "Toggle DevTools", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let tray_menu = Menu::with_items(app, &[
                &dashboard_item,
                &protection_item,
                &settings_item,
                &PredefinedMenuItem::separator(app)?,
                &devtools_item,
                &PredefinedMenuItem::separator(app)?,
                &quit_item,
            ])?;

            println!("✅ Tray menu created");

            let app_devtools_item =
                MenuItem::with_id(app, "toggle_devtools", "Toggle DevTools", true, None::<&str>)?;
            let app_menu = Menu::with_items(app, &[
                &PredefinedMenuItem::separator(app)?,
                &app_devtools_item,
            ])?;
            app.set_menu(app_menu)?;

            println!("✅ App menu set");

            let _tray = TrayIconBuilder::new()
                .menu(&tray_menu)
                .tooltip("CyberGuardian XDR")
                .on_tray_icon_event(|tray, event| {
                    println!("🖱️ Tray icon event: {:?}", event);

                    match event {
                        TrayIconEvent::Click { button, button_state, .. } => {
                            println!(
                                "🖱️ Click detected - Button: {:?}, State: {:?}",
                                button, button_state
                            );

                            if button == MouseButton::Right
                                && button_state == MouseButtonState::Down
                            {
                                println!("🖱️ Right click detected - menu should show");
                            }

                            if button == MouseButton::Left
                                && button_state == MouseButtonState::Down
                            {
                                println!("🖱️ Left click detected");
                                if let Some(window) = tray.app_handle().get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                        }
                        _ => {}
                    }
                })
                .on_menu_event(|app, event| {
                    println!("🖱️ Menu event: {}", event.id.as_ref());
                    match event.id.as_ref() {
                        "dashboard" => {
                            println!("📊 Opening dashboard...");
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "settings" => {
                            println!("⚙️ Opening settings...");
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "toggle_devtools" => {
                            println!("🛠️ Toggling DevTools...");
                            if let Some(window) = app.get_webview_window("main") {
                                window.open_devtools();
                            }
                        }
                        "quit" => {
                            println!("🛑 Quitting...");
                            std::process::exit(0);
                        }
                        _ => {
                            println!("❓ Unknown menu item: {}", event.id.as_ref());
                        }
                    }
                })
                .build(app)?;

            println!("✅ Tray icon created");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                println!("🔒 Window close requested - hiding instead");
                window.hide().unwrap();
                api.prevent_close();
            }
        })
       .invoke_handler(tauri::generate_handler![
    greet,
    start_file_protection,
    create_quarantine_record,
    start_local_scan,
    scan_windows_registry,
    scan_windows_services,
    scan_windows_tasks,
    // Process Protection Commands
    init_tamper_protection,
    get_desktop_protection_status,
    enable_desktop_max_protection,
    disable_desktop_protection,
    check_admin_privileges,
    enable_anti_termination_desktop,
    enable_self_healing_desktop,
    install_service_desktop,
    // Service Management Commands
    check_service_installed,
    check_service_running,
    get_service_status,
    start_service_command,
    stop_service_command,
    uninstall_service_command,
    // Process Monitoring Commands
    get_windows_processes,
    get_process_stats,
    // Deep Quarantine Commands
    deep_quarantine_analyze,
    deep_quarantine_remove,
    deep_quarantine_list_backups
])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}