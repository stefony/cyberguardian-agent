//! Background tasks for periodic data synchronization with backend

use std::time::Duration;
use tokio::time;

/// Start background process upload task
/// Sends process list to backend every 30 seconds
pub fn start_process_upload_task(api_token: String) {
    tokio::spawn(async move {
        println!("🚀 Background process upload task started");
        
        let mut interval = time::interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            // Get current processes
            let processes = match crate::process_monitor::enumerate_processes() {
                Ok(procs) => procs,
                Err(e) => {
                    eprintln!("❌ Failed to enumerate processes: {}", e);
                    continue;
                }
            };
            
            println!("📤 Uploading {} processes to backend...", processes.len());
            
            // Convert to API format
            let api_processes: Vec<crate::api_client::ProcessInfo> = processes
                .into_iter()
                .map(|p| crate::api_client::ProcessInfo {
                    pid: p.pid,
                    name: p.name,
                    parent_pid: p.parent_pid,
                    thread_count: p.thread_count,
                    exe_path: p.exe_path,
                })
                .collect();
            
            // Send to backend
            match crate::api_client::send_processes_to_backend(api_processes, &api_token).await {
                Ok(_) => {
                    println!("✅ Processes uploaded successfully");
                }
                Err(e) => {
                    eprintln!("❌ Failed to upload processes: {}", e);
                }
            }
        }
    });
}

/// Test backend connection on startup
pub async fn test_connection(api_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔌 Testing backend connection...");
    
    match crate::api_client::test_backend_connection(api_token).await {
        Ok(true) => {
            println!("✅ Backend connection successful");
            Ok(())
        }
        Ok(false) => {
            eprintln!("⚠️ Backend returned non-success status");
            Err("Backend not reachable".into())
        }
        Err(e) => {
            eprintln!("❌ Backend connection failed: {}", e);
            Err(e)
        }
    }
}