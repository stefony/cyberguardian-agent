//! Real Windows Process Monitoring
//! Enumerates running processes and detects suspicious activity

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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

/// Кеш за CPU times между извикванията
struct CpuCache {
    times: HashMap<u32, (u64, std::time::Instant)>,
}

lazy_static::lazy_static! {
    static ref CPU_CACHE: Mutex<CpuCache> = Mutex::new(CpuCache {
        times: HashMap::new(),
    });
}

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

/// Get raw CPU time for a process (no sleep)
#[cfg(target_os = "windows")]
fn get_raw_cpu_time(pid: u32) -> u64 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return 0,
        };

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();

        let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let _ = CloseHandle(handle);

        if result.is_ok() {
            filetime_to_u64(kernel).saturating_add(filetime_to_u64(user))
        } else {
            0
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_raw_cpu_time(_pid: u32) -> u64 {
    0
}

/// Calculate CPU percent using cached previous measurement
fn calculate_cpu_percent(pid: u32) -> f32 {
    let current_time = get_raw_cpu_time(pid);
    let now = std::time::Instant::now();

    let mut cache = match CPU_CACHE.lock() {
        Ok(c) => c,
        Err(_) => return 0.0,
    };

    let cpu = if let Some((prev_time, prev_instant)) = cache.times.get(&pid) {
        let elapsed_ns = now.duration_since(*prev_instant).as_nanos() as f64;
        let cpu_delta = current_time.saturating_sub(*prev_time) as f64;

        if elapsed_ns > 0.0 {
            // FILETIME е в 100ns единици, elapsed_ns е в 1ns
            let cpu = (cpu_delta * 100.0 / (elapsed_ns / 100.0)) as f32;
            let num_cpus = num_cpus::get() as f32;
            (cpu / num_cpus).min(100.0).max(0.0)
        } else {
            0.0
        }
    } else {
        0.0  // Първо извикване — няма предишна стойност
    };

    // Обновяваме кеша
    cache.times.insert(pid, (current_time, now));
    cpu
}

/// Get memory usage for a process (in MB)
#[cfg(target_os = "windows")]
fn get_memory_usage(pid: u32) -> f64 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
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
                let cpu_percent = calculate_cpu_percent(pid);

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