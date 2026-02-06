use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::sync::mpsc::channel;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::fs;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use std::io::Read;

// Global cache of scanned files (path -> hash)
lazy_static::lazy_static! {
    static ref SCANNED_FILES: Arc<Mutex<HashMap<String, String>>> = 
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub timestamp: String,
    pub event_type: String,
    pub file_path: String,
    pub file_size: Option<u64>,
    pub file_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanRequest {
    file_path: String,
    file_size: u64,
}

pub fn start_watching(paths: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Starting file watcher for paths: {:?}", paths);
    
    // Clone paths for threads
    let paths_clone = paths.clone();
    let paths_for_scan = paths.clone();
    
    // ✅ STEP 1: Initial scan in BACKGROUND thread (non-blocking)
    std::thread::spawn(move || {
        println!("🔎 Performing smart initial scan in background...");
        for path_str in &paths_for_scan {
            scan_directory(Path::new(path_str));
        }
        println!("✅ Initial scan completed");
    });
    
    // ✅ STEP 2: Start watcher immediately (doesn't block)
    std::thread::spawn(move || {
        let (tx, rx) = channel();
        
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    println!("📁 File event detected: {:?}", event);
                    tx.send(event).ok();
                }
                Err(e) => println!("❌ Watch error: {:?}", e),
            }
        }).expect("Failed to create watcher");
        
        // Watch each path
        for path in paths_clone {
            println!("👀 Watching: {}", path);
            watcher.watch(Path::new(&path), RecursiveMode::Recursive)
                .expect("Failed to watch path");
        }
        
        // Keep watcher alive and process events
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    process_event(event);
                }
                Err(_) => {
                    // Timeout, continue watching
                    continue;
                }
            }
        }
    });
    
    Ok(())
}

// ✅ SMART: Recursively scan directory with hash checking
fn scan_directory(dir: &Path) {
    if !dir.is_dir() {
        // Single file
        scan_file(dir);
        return;
    }
    
    // Read directory entries
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            println!("❌ Failed to read directory {:?}: {}", dir, e);
            return;
        }
    };
    
    for entry in entries.flatten() {
        let path = entry.path();
        
        if path.is_dir() {
            // Recursive scan subdirectories
            scan_directory(&path);
        } else if path.is_file() {
            scan_file(&path);
        }
    }
}

// ✅ SMART: Calculate SHA256 hash of file
fn calculate_file_hash(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192]; // 8KB buffer
    
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}

// ✅ SMART: Scan file only if new or modified
fn scan_file(path: &Path) {
    // Get file metadata
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            println!("❌ Failed to get metadata for {:?}: {}", path, e);
            return;
        }
    };
    
    let file_size = metadata.len();
    
    // Skip very large files (>100MB)
    if file_size > 100_000_000 {
        println!("⏭️ Skipping large file: {:?} ({}MB)", path, file_size / 1_000_000);
        return;
    }
    
    // Skip system/hidden files
    if let Some(filename) = path.file_name() {
        let name = filename.to_string_lossy();
        if name.starts_with('.') || name.starts_with('~') {
            return;
        }
    }
    
    let path_str = path.to_string_lossy().to_string();
    
    // ✅ SMART: Calculate file hash
    let hash = match calculate_file_hash(path) {
        Ok(h) => h,
        Err(e) => {
            println!("❌ Failed to calculate hash for {:?}: {}", path, e);
            return;
        }
    };
    
    // ✅ SMART: Check if already scanned with same hash
    {
        let mut cache = SCANNED_FILES.lock().unwrap();
        if let Some(cached_hash) = cache.get(&path_str) {
            if cached_hash == &hash {
                println!("⏭️ File already scanned (hash match), skipping: {:?}", path);
                return;
            } else {
                println!("🔄 File modified (hash changed), re-scanning: {:?}", path);
            }
        }
        
        // Update cache BEFORE scanning (to prevent double-scan)
        cache.insert(path_str.clone(), hash.clone());
    }
    
    println!("📂 Scanning file: {:?} ({}KB)", path, file_size / 1024);
    
    // Send to Railway backend for analysis
    send_to_backend(path, file_size);
}

// ✅ Send file to Railway API for ML analysis
fn send_to_backend(path: &Path, file_size: u64) {
    let path_str = path.to_string_lossy().to_string();
    
    // Spawn async task to not block file watcher
    std::thread::spawn(move || {
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build() {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Failed to create HTTP client: {}", e);
                return;
            }
        };
        
        let backend_url = std::env::var("RAILWAY_BACKEND_URL")
            .unwrap_or_else(|_| "https://cyberguardian-backend-production.up.railway.app".to_string());
        
        let scan_url = format!("{}/api/protection/scan", backend_url);
        
        let request_body = ScanRequest {
            file_path: path_str.clone(),
            file_size,
        };
        
        let token = get_auth_token();
        
        let response = client
            .post(&scan_url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .json(&request_body)
            .send();
        
        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    println!("✅ File scanned successfully: {}", path_str);
                    
                    if let Ok(body) = resp.text() {
                        println!("📊 Scan result: {}", body);
                        
                        // ✅ PARSE RESPONSE & AUTO-QUARANTINE
                        if let Ok(scan_result) = serde_json::from_str::<serde_json::Value>(&body) {
                            if let Some(data) = scan_result.get("data") {
                                if let Some(threat_score) = data.get("threat_score").and_then(|v| v.as_f64()) {
                                    println!("🎯 Threat score: {}", threat_score);
                                    
                                    // Auto-quarantine if threat score >= 80
                                    if threat_score >= 70.0 {
                                        println!("⚠️ HIGH THREAT DETECTED! Auto-quarantining file...");
                                        quarantine_file(&path_str, threat_score, file_size);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    println!("⚠️ Scan failed with status {}: {}", resp.status(), path_str);
                }
            }
            Err(e) => {
                println!("❌ Network error scanning file {}: {}", path_str, e);
            }
        }
    });
}

// ✅ QUARANTINE FILE - Backend handles physical move + DB record
fn quarantine_file(file_path: &str, threat_score: f64, file_size: u64) {
    let backend_url = std::env::var("RAILWAY_BACKEND_URL")
        .unwrap_or_else(|_| "https://cyberguardian-backend-production.up.railway.app".to_string());
    let token = get_auth_token();
    
    // Determine threat level
    let threat_level = if threat_score >= 90.0 {
        "CRITICAL"
    } else if threat_score >= 80.0 {
        "HIGH"
    } else if threat_score >= 60.0 {
        "MEDIUM"
    } else {
        "LOW"
    };
    
    // Create JSON payload
  let payload = serde_json::json!({
    "file_path": file_path,
    "reason": "Auto-quarantine: High threat detected",
    "threat_score": threat_score,
    "threat_level": threat_level,
    "detection_method": "ML-powered scan",
    "file_size": file_size
    }); 
    // Send POST request - backend will handle physical quarantine
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/api/quarantine/", backend_url);
    
    println!("🔍 DEBUG: Preparing quarantine API call");
    println!("🔍 URL: {}", url);
    println!("🔍 Token length: {}", token.len());
    println!("🔍 Token first 50 chars: {}", &token[..50.min(token.len())]);
    println!("🔍 Payload: {:?}", payload);

    match client.post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .json(&payload)
        .send() {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("✅ Quarantine record created in backend (file moved by backend)");
            } else {
                println!("⚠️ Failed to create backend record: {}", resp.status());
            }
        }
        Err(e) => {
            println!("❌ Network error creating backend record: {}", e);
        }
    }
}

// ✅ Process real-time file events
fn process_event(event: Event) {
    match event.kind {
        EventKind::Create(_) => {
            for path in event.paths {
                if path.is_file() {
                    println!("✅ File created: {:?}", path);
                    scan_file(&path);
                }
            }
        }
        EventKind::Modify(_) => {
            for path in event.paths {
                if path.is_file() {
                    println!("✏️ File modified: {:?}", path);
                    scan_file(&path);
                }
            }
        }
        EventKind::Remove(_) => {
            for path in event.paths {
                println!("🗑️ File removed: {:?}", path);
                
                // Remove from cache
                let path_str = path.to_string_lossy().to_string();
                SCANNED_FILES.lock().unwrap().remove(&path_str);
            }
        }
        _ => {}
    }
}
fn get_auth_token() -> String {
    // Read token from environment variable (set by start_file_protection)
    std::env::var("AUTH_TOKEN")
        .unwrap_or_else(|_| {
            println!("⚠️ AUTH_TOKEN not found in environment, using empty token");
            String::new()
        })
}