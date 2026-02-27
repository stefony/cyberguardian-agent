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
    PROCESS_QUERY_INFORMATION, PROCESS_ACCESS_RIGHTS,
};
#[cfg(target_os = "windows")]
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY};

#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x1000);

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

#[cfg(target_os = "windows")]
fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

#[cfg(target_os = "windows")]
fn get_raw_cpu_time(pid: u32) -> u64 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED, false, pid) {
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

        if elapsed_ns > 0.0 && cpu_delta > 0.0 {
            let num_cpus = num_cpus::get() as f32;
            let cpu = (cpu_delta * 100.0 / (elapsed_ns / 100.0)) as f32;
            (cpu / num_cpus).min(100.0).max(0.0)
        } else {
            0.0
        }
    } else {
        0.0
    };

    cache.times.insert(pid, (current_time, now));
    cpu
}

/// Get memory usage for a process (in MB)
#[cfg(target_os = "windows")]
fn get_memory_usage(pid: u32) -> f64 {
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED, false, pid) {
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
#[cfg(target_os = "windows")]
fn get_process_cmdline(pid: u32) -> String {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows::Win32::Foundation::CloseHandle;
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    unsafe {
        let handle = match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => return String::new(),
        };

        #[repr(C)]
        struct PROCESS_BASIC_INFORMATION {
            reserved1: *mut std::ffi::c_void,
            peb_base_address: *mut u8,
            reserved2: [*mut std::ffi::c_void; 2],
            unique_process_id: usize,
            reserved3: *mut std::ffi::c_void,
        }

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );

        if status.is_err() {
            let _ = CloseHandle(handle);
            return String::new();
        }

        // Четем PEB
        let mut peb = vec![0u8; 0x60];
        let mut bytes_read: usize = 0;
        if ReadProcessMemory(
            handle,
            pbi.peb_base_address as *const _,
            peb.as_mut_ptr() as *mut _,
            peb.len(),
            Some(&mut bytes_read),
        ).is_err() {
            let _ = CloseHandle(handle);
            return String::new();
        }

        // ProcessParameters offset = 0x20 (x64)
        let proc_params_ptr = usize::from_le_bytes(peb[0x20..0x28].try_into().unwrap_or([0;8]));
        if proc_params_ptr == 0 {
            let _ = CloseHandle(handle);
            return String::new();
        }

        // Четем ProcessParameters
        let mut params = vec![0u8; 0x80];
        if ReadProcessMemory(
            handle,
            proc_params_ptr as *const _,
            params.as_mut_ptr() as *mut _,
            params.len(),
            Some(&mut bytes_read),
        ).is_err() {
            let _ = CloseHandle(handle);
            return String::new();
        }

        // CommandLine UNICODE_STRING offset = 0x70 (x64)
        let cmdline_len = u16::from_le_bytes(params[0x70..0x72].try_into().unwrap_or([0;2])) as usize;
        let cmdline_ptr = usize::from_le_bytes(params[0x78..0x80].try_into().unwrap_or([0;8]));

        if cmdline_len == 0 || cmdline_ptr == 0 {
            let _ = CloseHandle(handle);
            return String::new();
        }

        let mut cmdline_buf = vec![0u8; cmdline_len];
        let result = if ReadProcessMemory(
            handle,
            cmdline_ptr as *const _,
            cmdline_buf.as_mut_ptr() as *mut _,
            cmdline_len,
            Some(&mut bytes_read),
        ).is_ok() {
            let wide: Vec<u16> = cmdline_buf.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&wide).to_string()
        } else {
            String::new()
        };

        let _ = CloseHandle(handle);
        result
    }
}

#[cfg(not(target_os = "windows"))]
fn get_process_cmdline(_pid: u32) -> String {
    String::new()
}

#[cfg(not(target_os = "windows"))]
fn get_process_cmdline(_pid: u32) -> String {
    String::new()
}

#[cfg(not(target_os = "windows"))]
fn get_process_cmdline(_pid: u32) -> String {
    String::new()
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
                    exe_path: get_process_cmdline(pid),
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

// ============================================================================
// RULES ENGINE — Detection patterns за всички TTPs
// ============================================================================

/// Решение от rules engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDecision {
    pub is_threat: bool,
    pub reason: String,
    pub mitre: String,
    pub severity: String,
}

/// Блокиран процес — записва се в памет и се репортва
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedProcess {
    pub pid: u32,
    pub process_name: String,
    pub parent_name: String,
    pub reason: String,
    pub mitre_technique: String,
    pub severity: String,
    pub timestamp: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Анализира процес и връща ThreatDecision
pub fn analyze_process(name: &str, cmdline: &str, parent_name: &str) -> ThreatDecision {
    let name_l = name.to_lowercase();
    let cmd_l = cmdline.to_lowercase();
    let parent_l = parent_name.to_lowercase();

    // ── T1003 Credential Dumping ─────────────────────────────────────────
    let cred_names = ["mimikatz", "procdump", "pwdump", "wce.exe", "gsecdump", "fgdump"];
    for n in &cred_names {
        if name_l.contains(n) {
            return ThreatDecision {
                is_threat: true,
                reason: format!("Known credential dumping tool: {}", name),
                mitre: "T1003".to_string(),
                severity: "critical".to_string(),
            };
        }
    }
    let cred_cmd = [
        "sekurlsa::logonpasswords", "lsadump::sam", "lsadump::dcsync",
        "invoke-mimikatz", "privilege::debug", "procdump.*lsass",
        "comsvcs.*minidump", "reg save.*sam", "reg save.*system",
    ];
    for p in &cred_cmd {
        if cmd_l.contains(p) {
            return ThreatDecision {
                is_threat: true,
                reason: format!("Credential dumping pattern: {}", p),
                mitre: "T1003".to_string(),
                severity: "critical".to_string(),
            };
        }
    }

    // ── T1059.001 PowerShell Abuse ────────────────────────────────────────
    if name_l.contains("powershell") {
        let critical = [
            "invoke-mimikatz", "invoke-bloodhound", "sharphound",
            "frombase64string", "invoke-expression", "iex(",
            "downloadstring", "-encodedcommand", "-enc ",
            "set-mppreference", "amsiutils", "sekurlsa",
        ];
        for p in &critical {
            if cmd_l.contains(p) {
                return ThreatDecision {
                    is_threat: true,
                    reason: format!("Malicious PowerShell: {}", p),
                    mitre: "T1059.001".to_string(),
                    severity: "critical".to_string(),
                };
            }
        }
        let high = ["-windowstyle hidden", "bypass", "new-object net.webclient",
                    "invoke-webrequest", "start-bitstransfer"];
        for p in &high {
            if cmd_l.contains(p) {
                return ThreatDecision {
                    is_threat: true,
                    reason: format!("Suspicious PowerShell: {}", p),
                    mitre: "T1059.001".to_string(),
                    severity: "high".to_string(),
                };
            }
        }
    }

    // ── T1047 WMI Abuse ───────────────────────────────────────────────────
    if name_l.contains("wmic") {
        let wmi = ["process call create", "shadowcopy delete", "/node:", "/format:"];
        for p in &wmi {
            if cmd_l.contains(p) {
                return ThreatDecision {
                    is_threat: true,
                    reason: format!("WMI abuse: {}", p),
                    mitre: "T1047".to_string(),
                    severity: "critical".to_string(),
                };
            }
        }
    }

    // ── T1218 LOLBins ─────────────────────────────────────────────────────
    let lolbins: &[(&str, &[&str])] = &[
        ("certutil.exe",  &["-urlcache", "-decode", "-f http", "-f https"]),
        ("mshta.exe",     &["http://", "https://", "javascript:", "vbscript:"]),
        ("regsvr32.exe",  &["/i:http", "/i:https", "scrobj.dll"]),
        ("rundll32.exe",  &["javascript:", "vbscript:", "http://"]),
        ("bitsadmin.exe", &["/transfer", "/download"]),
    ];
    for (lolbin, patterns) in lolbins {
        if name_l.contains(lolbin) {
            for p in *patterns {
                if cmd_l.contains(p) {
                    return ThreatDecision {
                        is_threat: true,
                        reason: format!("LOLBin abuse: {} with {}", name, p),
                        mitre: "T1218".to_string(),
                        severity: "critical".to_string(),
                    };
                }
            }
        }
    }

    // ── T1562 Defense Impairment ──────────────────────────────────────────
    let impair = [
        "set-mppreference.*disable", "sc stop windefend",
        "netsh.*firewall.*disable", "bcdedit.*recoveryenabled.*no",
        "vssadmin.*delete shadows", "wevtutil.*clear-log",
        "reg add.*disableantispyware", "reg add.*disableantivirus",
    ];
    for p in &impair {
        if cmd_l.contains(&p.replace(".*", "")) {
            return ThreatDecision {
                is_threat: true,
                reason: format!("Defense impairment: {}", p),
                mitre: "T1562".to_string(),
                severity: "critical".to_string(),
            };
        }
    }

    // ── T1547 / T1053 Persistence ─────────────────────────────────────────
    let persist = [
        "schtasks /create", "schtasks/create",
        "reg add.*currentversion\\run",
        "reg add.*winlogon",
    ];
    for p in &persist {
        if cmd_l.contains(p) {
            return ThreatDecision {
                is_threat: true,
                reason: format!("Persistence mechanism: {}", p),
                mitre: "T1547".to_string(),
                severity: "high".to_string(),
            };
        }
    }

    // ── T1059 Suspicious parent→child chains ─────────────────────────────
    let chains: &[(&str, &[&str])] = &[
        ("winword.exe",  &["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"]),
        ("excel.exe",    &["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"]),
        ("outlook.exe",  &["powershell.exe", "cmd.exe", "mshta.exe"]),
        ("wmiprvse.exe", &["powershell.exe", "cmd.exe", "wscript.exe"]),
        ("chrome.exe",   &["powershell.exe", "cmd.exe", "wscript.exe"]),
    ];
    for (parent, children) in chains {
        if parent_l.contains(parent) {
            for child in *children {
                if name_l.contains(child) {
                    return ThreatDecision {
                        is_threat: true,
                        reason: format!("Suspicious chain: {} → {}", parent_name, name),
                        mitre: "T1059".to_string(),
                        severity: "high".to_string(),
                    };
                }
            }
        }
    }

    // Clean
    ThreatDecision {
        is_threat: false,
        reason: String::new(),
        mitre: String::new(),
        severity: String::new(),
    }
}

/// Kill процес по PID
#[cfg(target_os = "windows")]
pub fn block_process(pid: u32) -> Result<(), String> {
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("OpenProcess failed: {:?}", e))?;
        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        result.map_err(|e| format!("TerminateProcess failed: {:?}", e))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn block_process(pid: u32) -> Result<(), String> {
    Err(format!("Blocking not supported on this platform (PID: {})", pid))
}
// ============================================================================
// GLOBAL MONITOR STATE + BACKGROUND LOOP (500ms polling)
// ============================================================================

use std::sync::atomic::{AtomicBool, Ordering};

/// Глобален state на монитора
pub struct MonitorState {
    pub blocking_enabled: bool,
    pub blocked_processes: Vec<BlockedProcess>,
    pub threats_detected: u64,
    pub processes_blocked: u64,
}

lazy_static::lazy_static! {
    static ref MONITOR_STATE: Mutex<MonitorState> = Mutex::new(MonitorState {
        blocking_enabled: false,
        blocked_processes: Vec::new(),
        threats_detected: 0,
        processes_blocked: 0,
    });

    static ref MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
}

/// Стартира background monitoring loop
pub fn start_monitor_loop() {
    if MONITOR_RUNNING.load(Ordering::SeqCst) {
        println!("⚠️ Monitor loop already running");
        return;
    }

    MONITOR_RUNNING.store(true, Ordering::SeqCst);

    std::thread::spawn(|| {
        println!("🔄 Process monitor loop started (500ms interval)");

        // Вземи snapshot на съществуващите процеси — не ги анализираме
        let mut known_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        if let Ok(procs) = get_running_processes() {
            for p in procs {
                known_pids.insert(p.pid);
            }
        }
        println!("✅ {} existing processes ignored", known_pids.len());

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));

            if !MONITOR_RUNNING.load(Ordering::SeqCst) {
                break;
            }

            // Вземи текущите процеси
            let current_procs = match get_running_processes() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Намери новите
            let mut new_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
            for proc in &current_procs {
                new_pids.insert(proc.pid);

                if known_pids.contains(&proc.pid) {
                    continue; // Вече знаем за него
                }

                // НОВ ПРОЦЕС — анализирай го
                let parent_name = current_procs.iter()
                    .find(|p| p.pid == proc.parent_pid)
                    .map(|p| p.name.as_str())
                    .unwrap_or("unknown");

                let cmdline = if is_suspicious_name(&proc.name) {
                    get_process_cmdline(proc.pid)
                 } else {
                      String::new()
                        };
                let decision = analyze_process(&proc.name, &cmdline, parent_name);

                if decision.is_threat {
                    println!(
                        "🚨 THREAT: {} (PID {}) — {} [{}]",
                        proc.name, proc.pid, decision.reason, decision.mitre
                    );

                    let blocking = {
                        MONITOR_STATE.lock()
                            .map(|s| s.blocking_enabled)
                            .unwrap_or(false)
                    };

                    let (success, error) = if blocking && decision.severity == "critical" {
                        match block_process(proc.pid) {
                            Ok(()) => {
                                println!("🚫 BLOCKED: {} (PID {})", proc.name, proc.pid);
                                (true, None)
                            }
                            Err(e) => {
                                println!("⚠️ Block failed: {}", e);
                                (false, Some(e))
                            }
                        }
                    } else {
                        (false, None)
                    };

                    let record = BlockedProcess {
                        pid: proc.pid,
                        process_name: proc.name.clone(),
                        parent_name: parent_name.to_string(),
                        reason: decision.reason.clone(),
                        mitre_technique: decision.mitre.clone(),
                        severity: decision.severity.clone(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        success,
                        error,
                    };

                    if let Ok(mut state) = MONITOR_STATE.lock() {
                        state.threats_detected += 1;
                        if success { state.processes_blocked += 1; }
                        state.blocked_processes.push(record);
                        // Max 500 записа
                        if state.blocked_processes.len() > 500 {
                            state.blocked_processes.remove(0);
                        }
                    }
                }
            }

            known_pids = new_pids;
        }

        println!("🛑 Monitor loop stopped");
    });
}

/// Спира monitoring loop
pub fn stop_monitor_loop() {
    MONITOR_RUNNING.store(false, Ordering::SeqCst);
}

/// Enable blocking
pub fn enable_blocking() {
    if let Ok(mut state) = MONITOR_STATE.lock() {
        state.blocking_enabled = true;
        println!("🚫 Runtime blocking: ENABLED");
    }
}

/// Disable blocking
pub fn disable_blocking() {
    if let Ok(mut state) = MONITOR_STATE.lock() {
        state.blocking_enabled = false;
        println!("✅ Runtime blocking: DISABLED (detection only)");
    }
}

/// Вземи blocking статус
pub fn get_blocking_status() -> (bool, Vec<BlockedProcess>, u64) {
    if let Ok(state) = MONITOR_STATE.lock() {
        let last_20: Vec<BlockedProcess> = state.blocked_processes
            .iter().rev().take(20).cloned().collect();
        (state.blocking_enabled, last_20, state.threats_detected)
    } else {
        (false, vec![], 0)
    }
}
fn is_suspicious_name(name: &str) -> bool {
    let n = name.to_lowercase();
    ["powershell", "cmd", "wmic", "mshta", "certutil",
     "regsvr32", "rundll32", "bitsadmin", "wscript", "cscript",
     "mimikatz", "procdump", "pwdump"].iter().any(|s| n.contains(s))
}