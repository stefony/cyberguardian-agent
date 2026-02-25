//! Real Windows Process Monitoring
//! Enumerates running processes and detects suspicious activity

use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::thread;

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE, FILETIME};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, GetProcessTimes,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY};

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

/// Helper: convert FILETIME to u64
#[cfg(target_os = "windows")]
fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Get CPU usage for a process (two-pass measurement with wall clock)
#[cfg(target_os = "windows")]
fn get_cpu_usage(pid: u32) -> f32 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(h) => h,
            Err(_) => return 0.0,
        };

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel1 = FILETIME::default();
        let mut user1 = FILETIME::default();

        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel1, &mut user1).is_err() {
            let _ = CloseHandle(handle);
            return 0.0;
        }

        let proc_time1 = filetime_to_u64(kernel1) + filetime_to_u64(user1);
        let wall1 = std::time::Instant::now();

        thread::sleep(Duration::from_millis(150));

        let mut kernel2 = FILETIME::default();
        let mut user2 = FILETIME::default();

        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel2, &mut user2).is_err() {
            let _ = CloseHandle(handle);
            return 0.0;
        }

        let _ = CloseHandle(handle);

        let proc_time2 = filetime_to_u64(kernel2) + filetime_to_u64(user2);
        let wall_elapsed = wall1.elapsed().as_nanos() as f32 / 100.0; // конвертираме в 100ns units

        let proc_delta = proc_time2.saturating_sub(proc_time1) as f32;

        if wall_elapsed == 0.0 {
            return 0.0;
        }

        let num_cpus = num_cpus::get() as f32;
        let cpu = (proc_delta / wall_elapsed) * 100.0 / num_cpus;
        cpu.min(100.0).max(0.0)
    }
}

#[cfg(not(target_os = "windows"))]
fn get_cpu_usage(_pid: u32) -> f32 {
    0.0
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
            mem_counters.WorkingSetSize as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_memory_usage(_pid: u32) -> f64 {
    0.0
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

        "User".to_string()
    }
}

#[cfg(not(target_os = "windows"))]
fn get_username(_pid: u32) -> String {
    "N/A".to_string()
}

/// Enumerate all running Windows processes
#[cfg(target_os = "windows")]
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, String> {
    use std::mem;

    println!("🔍 Starting Windows process enumeration...");

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("Failed to create process snapshot: {:?}", e))?;

        if snapshot.is_invalid() {
            return Err("Invalid snapshot handle".to_string());
        }

        let mut processes = Vec::new();
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile
                        .iter()
                        .take_while(|&&c| c != 0)
                        .copied()
                        .collect::<Vec<u16>>()
                );

                let pid = entry.th32ProcessID;
                let memory_mb = get_memory_usage(pid);
                let username = get_username(pid);
                let cpu_percent = get_cpu_usage(pid);

                let process = ProcessInfo {
                    pid,
                    name: name.clone(),
                    parent_pid: entry.th32ParentProcessID,
                    thread_count: entry.cntThreads,
                    exe_path: name.clone(),
                    cpu_percent,
                    memory_mb,
                    username,
                };

                processes.push(process);

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