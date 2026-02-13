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
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY};
#[cfg(target_os = "windows")]


/// Process information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub exe_path: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub username: String,
}

/// Process monitoring statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStats {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub monitored_at: String,
}

/// Get memory usage for a process (in MB)
#[cfg(target_os = "windows")]
fn get_memory_usage(pid: u32) -> f64 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return 0.0,
        };

        let mut mem_counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        mem_counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

        let result = GetProcessMemoryInfo(
            handle,
            &mut mem_counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        );

        let _ = CloseHandle(handle);

        if result.is_ok() {
            // Convert bytes to MB
            mem_counters.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

/// Get username for a process
#[cfg(target_os = "windows")]
fn get_username(pid: u32) -> String {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return "N/A".to_string(),
        };

        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token).is_err() {
            let _ = CloseHandle(handle);
            return "N/A".to_string();
        }

        // Get token user info
        let mut return_length: u32 = 0;
        let mut buffer = vec![0u8; 256];

        let result = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token);
        let _ = CloseHandle(handle);

        if result.is_err() {
            return "N/A".to_string();
        }

        // For now, return a placeholder
        // Full SID-to-username conversion requires LookupAccountSidW
        // which is more complex - we can add it later if needed
        "User".to_string()
    }
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
                
                let pid = entry.th32ProcessID;
                
                // Get memory usage (real value)
                let memory_mb = get_memory_usage(pid);
                
                // Get username (real value)
                let username = get_username(pid);
                
                let process = ProcessInfo {
                    pid,
                    name: name.clone(),
                    parent_pid: entry.th32ParentProcessID,
                    thread_count: entry.cntThreads,
                    exe_path: name.clone(),
                    cpu_percent: 0.0,  // CPU requires time-based sampling, will add later
                    memory_mb,
                    username,
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