//! Real Windows Process Monitoring
//! Enumerates running processes and detects suspicious activity

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;

/// Process information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub exe_path: String,
}

/// Process monitoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStats {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub monitored_at: String,
}

/// Enumerate all running Windows processes
#[cfg(target_os = "windows")]
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
    use std::mem;
    
    println!("🔍 Starting Windows process enumeration...");
    
    unsafe {
        // Create snapshot of all processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("Failed to create process snapshot: {:?}", e))?;
        
        if snapshot.is_invalid() {
            return Err("Invalid snapshot handle".to_string());
        }
        
        let mut processes = Vec::new();
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        
        // Get first process
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // Extract process name from wchar array
                let name = String::from_utf16_lossy(
                    &entry.szExeFile
                        .iter()
                        .take_while(|&&c| c != 0)
                        .copied()
                        .collect::<Vec<u16>>()
                );
                
                let process = ProcessInfo {
                    pid: entry.th32ProcessID,
                    name: name.clone(),
                    parent_pid: entry.th32ParentProcessID,
                    thread_count: entry.cntThreads,
                    exe_path: name, // For now, just use name. Can be enhanced later.
                };
                
                processes.push(process);
                
                // Get next process
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        
        let _ = CloseHandle(snapshot);
        
        println!("✅ Enumerated {} processes", processes.len());
        Ok(processes)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
    Err("Process enumeration only supported on Windows".to_string())
}

/// Get process monitoring statistics
pub fn get_process_statistics(processes: &[ProcessInfo]) -> ProcessStats {
    let suspicious_count = processes.iter()
        .filter(|p| is_suspicious_process(&p.name))
        .count();
    
    ProcessStats {
        total_processes: processes.len(),
        suspicious_processes: suspicious_count,
        monitored_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Check if a process name is suspicious
fn is_suspicious_process(name: &str) -> bool {
    let suspicious_names = [
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
    ];
    
    let name_lower = name.to_lowercase();
    suspicious_names.iter().any(|&s| name_lower.contains(s))
}

/// Get all running processes
pub fn get_running_processes() -> Result<Vec<ProcessInfo>, String> {
    enumerate_processes()
}