//! ETW Process Creation Monitor
//! Засича всеки нов процес при стартиране чрез Event Tracing for Windows

use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    WNODE_FLAG_TRACED_GUID, CONTROLTRACE_HANDLE, PROCESSTRACE_HANDLE,
    StartTraceW, ControlTraceW, EnableTraceEx2,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_STOP,
    EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESS_TRACE_MODE_EVENT_RECORD,
    EVENT_TRACE_LOGFILEW,
};
use windows::Win32::Foundation::*;
use windows::core::GUID;

static ETW_RUNNING: AtomicBool = AtomicBool::new(false);

// Microsoft-Windows-Kernel-Process GUID
const KERNEL_PROCESS_GUID: GUID = GUID {
    data1: 0x22FB2CD6,
    data2: 0x0E7B,
    data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};

// Microsoft-Windows-WMI-Activity GUID
const WMI_ACTIVITY_GUID: GUID = GUID {
    data1: 0x1418EF04,
    data2: 0xB0B4,
    data3: 0x4623,
    data4: [0xBF, 0x7E, 0xD7, 0x4A, 0xB4, 0x7B, 0xBD, 0xAA],
};

// Microsoft-Windows-Kernel-Registry GUID
const KERNEL_REGISTRY_GUID: GUID = GUID {
    data1: 0x70EB4F03,
    data2: 0xC1DE,
    data3: 0x4F73,
    data4: [0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD],
};

// Microsoft-Windows-Kernel-Network GUID
const KERNEL_NETWORK_GUID: GUID = GUID {
    data1: 0x7DD42A49,
    data2: 0x5329,
    data3: 0x4832,
    data4: [0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88],
};

// Microsoft-Windows-DNS-Client GUID
const DNS_CLIENT_GUID: GUID = GUID {
    data1: 0x1C95126E,
    data2: 0x7EEA,
    data3: 0x49A9,
    data4: [0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D],
};

pub fn start_etw_monitor() {
    if ETW_RUNNING.load(Ordering::SeqCst) {
        return;
    }
    ETW_RUNNING.store(true, Ordering::SeqCst);

    std::thread::spawn(|| {
        println!("🔬 ETW Process Monitor starting...");
        unsafe { run_etw_session(); }
    });
}

pub fn stop_etw_monitor() {
    ETW_RUNNING.store(false, Ordering::SeqCst);
}

#[cfg(target_os = "windows")]
unsafe fn run_etw_session() {
    use std::mem;

    const SESSION_NAME: &str = "CyberGuardianETW\0";
    let session_name_wide: Vec<u16> = SESSION_NAME.encode_utf16().collect();

    let buf_size = mem::size_of::<EVENT_TRACE_PROPERTIES>() + 512;
    let mut buf = vec![0u8; buf_size];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    (*props).Wnode.BufferSize = buf_size as u32;
    (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    (*props).Wnode.ClientContext = 1;
    (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    (*props).LoggerNameOffset = mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    let name_ptr = windows::core::PCWSTR(session_name_wide.as_ptr());

    // Stop existing session
    let _ = ControlTraceW(
        CONTROLTRACE_HANDLE::default(),
        name_ptr,
        props,
        EVENT_TRACE_CONTROL_STOP,
    );

    // Reset buffer
    let mut buf = vec![0u8; buf_size];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    (*props).Wnode.BufferSize = buf_size as u32;
    (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    (*props).Wnode.ClientContext = 1;
    (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    (*props).LoggerNameOffset = mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    let name_offset = mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name_dst = buf[name_offset..].as_mut_ptr() as *mut u16;
    std::ptr::copy_nonoverlapping(session_name_wide.as_ptr(), name_dst, session_name_wide.len());

    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    let mut session_handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE::default();

    let err = StartTraceW(&mut session_handle, name_ptr, props);
    if err.0 != 0 {
        println!("❌ ETW StartTrace failed: {}", err.0);
        return;
    }
    println!("✅ ETW session started");

    let result = EnableTraceEx2(
        session_handle,
        &KERNEL_PROCESS_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        4u8, // TRACE_LEVEL_INFORMATION
        0x10,
        0,
        0,
        None,
    );

    if result.0 != 0 {
        println!("❌ ETW EnableTrace failed: {}", result.0);
        return;
    }
    println!("✅ ETW Kernel-Process provider enabled");

    // Enable WMI Activity provider на същата сесия
    let wmi_result = EnableTraceEx2(
        session_handle,
        &WMI_ACTIVITY_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        4u8,
        0xFF,
        0,
        0,
        None,
    );

    if wmi_result.0 != 0 {
        println!("⚠️ WMI Activity provider failed: {} (non-critical)", wmi_result.0);
    } else {
        println!("✅ ETW WMI-Activity provider enabled");
    }

    // Enable Kernel-Registry provider
    let reg_result = EnableTraceEx2(
        session_handle,
        &KERNEL_REGISTRY_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        4u8,
        0xFF, // All registry keywords
        0,
        0,
        None,
    );

    if reg_result.0 != 0 {
        println!("⚠️ Kernel-Registry provider failed: {} (non-critical)", reg_result.0);
    } else {
        println!("✅ ETW Kernel-Registry provider enabled");
    }

    // Enable Kernel-Network provider
    let net_result = EnableTraceEx2(
        session_handle,
        &KERNEL_NETWORK_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        4u8,
        0x10, // TcpIp connect keyword
        0,
        0,
        None,
    );

    if net_result.0 != 0 {
        println!("⚠️ Kernel-Network provider failed: {} (non-critical)", net_result.0);
    } else {
        println!("✅ ETW Kernel-Network provider enabled");
    }

    // Enable DNS Client provider
    let dns_result = EnableTraceEx2(
        session_handle,
        &DNS_CLIENT_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
        4u8,
        0xFF,
        0,
        0,
        None,
    );

    if dns_result.0 != 0 {
        println!("⚠️ DNS-Client provider failed: {} (non-critical)", dns_result.0);
    } else {
        println!("✅ ETW DNS-Client provider enabled");
    }

    let mut log_file: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
    log_file.LoggerName = windows::core::PWSTR(session_name_wide.as_ptr() as *mut u16);
    log_file.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log_file.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    // OpenTraceW е достъпен само чрез raw binding
    type FnOpenTrace = unsafe extern "system" fn(*mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE;
    let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
        windows::core::w!("sechost.dll")
    );

    let open_trace_fn: Option<FnOpenTrace> = match ntdll {
        Ok(h) => {
            let addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                h, windows::core::s!("OpenTraceW")
            );
            addr.map(|f| std::mem::transmute(f))
        },
        Err(_) => None,
    };

    let trace_handle = match open_trace_fn {
        Some(f) => f(&mut log_file),
        None => {
            println!("❌ OpenTraceW not found");
            return;
        }
    };

    if trace_handle.Value == u64::MAX {
        println!("❌ ETW OpenTrace failed");
        return;
    }

    println!("🔬 ETW listening for process creation events...");

    let handles = [trace_handle];
    type FnProcessTrace = unsafe extern "system" fn(*const PROCESSTRACE_HANDLE, u32, *const i64, *const i64) -> u32;

    let process_trace_fn: Option<FnProcessTrace> = match windows::Win32::System::LibraryLoader::GetModuleHandleW(
        windows::core::w!("sechost.dll")
    ) {
        Ok(h) => {
            let addr = windows::Win32::System::LibraryLoader::GetProcAddress(
                h, windows::core::s!("ProcessTrace")
            );
            addr.map(|f| std::mem::transmute(f))
        },
        Err(_) => None,
    };

    if let Some(f) = process_trace_fn {
        f(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
    }

    let _ = ControlTraceW(
        session_handle,
        None,
        props,
        EVENT_TRACE_CONTROL_STOP,
    );

    println!("🛑 ETW Monitor stopped");
}

unsafe extern "system" fn etw_event_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }

    let event = &*event_record;
    let provider = event.EventHeader.ProviderId;

    if provider == KERNEL_PROCESS_GUID {
        if event.EventHeader.EventDescriptor.Id != 1 {
            return;
        }
        if event.UserDataLength < 8 || event.UserData.is_null() {
            return;
        }
        let data = std::slice::from_raw_parts(
            event.UserData as *const u8,
            event.UserDataLength as usize,
        );
        let new_pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let parent_pid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if new_pid == 0 || new_pid == 4 {
            return;
        }
         
        let image_name = if data.len() > 60 {
            let wide: Vec<u16> = data[60..].chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            let full = String::from_utf16_lossy(&wide);
             full.split('\\').last().unwrap_or("").to_string()
        } else {
            String::new()
        };
        // Suspend САМО suspicious процеси — не всички
        let name_lower = image_name.to_lowercase();
        let is_suspicious = ["powershell", "cmd", "wmic", "mshta", "certutil",
            "regsvr32", "rundll32", "wscript", "cscript", "mimikatz",
             "net", "wevtutil", "vssadmin", "bcdedit", "sc"]
            .iter().any(|s| name_lower.contains(s));
        if is_suspicious {
            suspend_process(new_pid);
        }
         let parent_name_for_handler = {
        let mut pname = get_process_name(parent_pid);
         if pname.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(5));
        pname = get_process_name(parent_pid);
        }
        pname
    };  
handle_new_process_with_name(new_pid, parent_pid, image_name, parent_name_for_handler);

    } else if provider == WMI_ACTIVITY_GUID {
        handle_wmi_event(event);
    } else if provider == KERNEL_REGISTRY_GUID {
        handle_registry_event(event);
    } else if provider == KERNEL_NETWORK_GUID {
        handle_network_event(event);
    } else if provider == DNS_CLIENT_GUID {
        handle_dns_event(event);
    }
}

fn handle_dns_event(event: &EVENT_RECORD) {
    use crate::process_monitor;

   let event_id = event.EventHeader.EventDescriptor.Id;
    println!("🔬 DNS Event ID={}", event_id);
    // Event ID 3006 = DNS Query
    if event_id != 3006 {
        return;
    }

    let pid = event.EventHeader.ProcessId;

    // Извличаме domain от UserData (UTF-16)
    let domain = if !event.UserData.is_null() && event.UserDataLength > 4 {
        unsafe {
            let data = std::slice::from_raw_parts(
                event.UserData as *const u8,
                event.UserDataLength as usize,
            );
            if data.len() >= 8 {
                let wide: Vec<u16> = data[4..].chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&wide).to_lowercase()
            } else {
                String::new()
            }
        }
    } else {
        String::new()
    };

    if domain.is_empty() {
        return;
    }

    println!("🔬 DNS: PID={} Query={}", pid, &domain[..domain.len().min(80)]);

    // DGA detection — домейни с много рандомни символи
    let is_dga = domain.len() > 20
        && !domain.contains("microsoft")
        && !domain.contains("windows")
        && !domain.contains("google")
        && !domain.contains("cloudflare")
        && !domain.contains("amazon");

    // DNS tunneling — TXT record abuse (дълги поддомейни)
    let is_tunneling = domain.split('.').any(|part| part.len() > 30);

    if is_dga || is_tunneling {
        println!("🚨 DNS THREAT: PID={} Domain={} [T1071.004]", pid, &domain[..domain.len().min(100)]);

        let name = get_process_name(pid);
        let parent_name = get_parent_name(pid);
        let reason = format!("Suspicious DNS query: {}", &domain[..domain.len().min(60)]);

        process_monitor::record_blocked_process(
            pid, &name, &parent_name,
            &reason,
            "T1071.004",
            "high",
            false,
            None,
        );
    }
}

fn handle_network_event(event: &EVENT_RECORD) {
    use crate::process_monitor;

    // Event ID 12 = TcpIpConnect, Event ID 15 = TcpIpConnectIPV6
    let event_id = event.EventHeader.EventDescriptor.Id;
    if event_id != 12 && event_id != 15 {
        return;
    }

    let pid = event.EventHeader.ProcessId;
    let name = get_process_name(pid);

    if name.is_empty() {
        return;
    }

    // Само suspicious процеси
    if !is_suspicious_name(&name) {
        return;
    }

    // Извличаме destination IP от UserData
    let dest_ip = if !event.UserData.is_null() && event.UserDataLength >= 20 {
        unsafe {
            let data = std::slice::from_raw_parts(
                event.UserData as *const u8,
                event.UserDataLength as usize,
            );
            // Destination IP е на offset 16 (4 bytes)
            format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19])
        }
    } else {
        String::from("unknown")
    };

    println!("🔬 NET: {} (PID={}) → {}", name, pid, dest_ip);

    // Засичаме suspicious outbound connections
    let is_suspicious = !dest_ip.starts_with("127.")
        && !dest_ip.starts_with("192.168.")
        && !dest_ip.starts_with("10.")
        && dest_ip != "unknown";

    if is_suspicious {
        println!("🚨 NETWORK THREAT: {} (PID={}) → {} [T1071]", name, pid, dest_ip);

        let parent_name = get_parent_name(pid);
        let reason = format!("Suspicious outbound connection to {}", dest_ip);

        process_monitor::record_blocked_process(
            pid, &name, &parent_name,
            &reason,
            "T1071",
            "high",
            false,
            None,
        );
    }
}

fn handle_registry_event(event: &EVENT_RECORD) {
    use crate::process_monitor;

    let event_id = event.EventHeader.EventDescriptor.Id;
    // 9=RegSetValue, 13=RegSetValue (x64)
    if event_id != 9 && event_id != 13 {
        return;
    }

    let pid = event.EventHeader.ProcessId;
    
    // Вземаме process name
    let name = get_process_name(pid);
    if name.is_empty() {
        return;
    }

    // Само suspicious процеси 
    if !is_suspicious_name(&name) {
        return;
    }

    // SUSPEND FIRST — преди да е излязъл
    let suspended = suspend_process(pid);

    // Вземаме cmdline и проверяваме за persistence patterns
    let cmdline = process_monitor::get_process_cmdline_pub(pid).to_lowercase();
    
    let is_persistence = cmdline.contains("currentversion\\run")
        || cmdline.contains("currentversion/run")
        || cmdline.contains("winlogon")
        || cmdline.contains("userinit");

   if is_persistence {
        println!("🚨 REGISTRY THREAT: {} (PID={}) CMD={}", name, pid, &cmdline[..cmdline.len().min(100)]);

        let parent_name = get_parent_name(pid);
        let _ = process_monitor::block_process(pid);
        println!("🚫 REGISTRY BLOCKED: {} (PID {})", name, pid);

        process_monitor::record_blocked_process(
            pid, &name, &parent_name,
            "Suspicious registry persistence key write",
            "T1547",
            "high",
            true,
            None,
        );
    } else if suspended {
        resume_process(pid);
    }
}

fn handle_wmi_event(event: &EVENT_RECORD) {
    use crate::process_monitor;

    let event_id = event.EventHeader.EventDescriptor.Id;
    let pid = event.EventHeader.ProcessId;

    let operation = if !event.UserData.is_null() && event.UserDataLength > 4 {
        unsafe {
            let data = std::slice::from_raw_parts(
                event.UserData as *const u8,
                event.UserDataLength as usize,
            );
            if data.len() >= 8 {
                let wide: Vec<u16> = data[4..].chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                String::from_utf16_lossy(&wide).to_lowercase()
            } else {
                String::new()
            }
        }
    } else {
        String::new()
    };

    if operation.is_empty() {
        return;
    }

    println!("🔬 WMI Event ID={} PID={} Op={}", event_id, pid, &operation[..operation.len().min(80)]);

    let is_malicious = (operation.contains("process") && operation.contains("create"))
        || operation.contains("win32_process")
        || operation.contains("shadowcopy")
        || operation.contains("/format:")
        || operation.contains("select * from win32_process");

    if is_malicious {
        println!("🚨 WMI THREAT: PID={} Operation={}", pid, &operation[..operation.len().min(100)]);

        let name = get_process_name(pid);
        let parent_name = get_parent_name(pid);

        let _ = process_monitor::block_process(pid);
        println!("🚫 WMI BLOCKED: {} (PID {})", name, pid);

        process_monitor::record_blocked_process(
            pid, &name, &parent_name,
            "Malicious WMI operation detected",
            "T1047",
            "critical",
            true,
            None,
        );
    }
}

fn handle_new_process_with_name(pid: u32, parent_pid: u32, image_name: String, known_parent: String) {
    use crate::process_monitor;

    let name = if image_name.is_empty() {
        get_process_name(pid)
    } else {
        image_name
    };

    if name.is_empty() { return; }

    println!("🔬 ETW: {} (PID {})", name, pid);

   if !is_suspicious_name(&name) { return; }

    let suspended = true; // suspend вече е направен в ETW callback-а

    let cmdline = {
    let mut cmd = process_monitor::get_process_cmdline_pub(pid);
   if cmd.is_empty() {
    std::thread::sleep(std::time::Duration::from_millis(5));
    cmd = process_monitor::get_process_cmdline_pub(pid);
}
if cmd.is_empty() {
    std::thread::sleep(std::time::Duration::from_millis(10));
    cmd = process_monitor::get_process_cmdline_pub(pid);
}
if cmd.is_empty() {
    std::thread::sleep(std::time::Duration::from_millis(20));
    cmd = process_monitor::get_process_cmdline_pub(pid);
}
    cmd
};
    let parent_name = if !known_parent.is_empty() {
    known_parent
    } else {
    get_process_name(parent_pid)
    };
 
   
    let decision = process_monitor::analyze_process(&name, &cmdline, &parent_name);

    if decision.is_threat {
        println!("🚨 ETW THREAT: {} — {} [{}]", name, decision.reason, decision.mitre);
        let _ = process_monitor::block_process(pid);
        println!("🚫 ETW BLOCKED: {} (PID {})", name, pid);
        process_monitor::record_blocked_process(
            pid, &name, &parent_name, &decision.reason,
            &decision.mitre, &decision.severity, true, None
        );
    } else if suspended {
        resume_process(pid);
    }
}

fn handle_new_process(pid: u32) {
    use crate::process_monitor;

    // SUSPEND FIRST — незабавно преди всичко
    let suspended = suspend_process(pid);

    // Вземи process name
    let name = get_process_name(pid);
    println!("🔬 ETW name for PID {}: '{}'", pid, name);
    if name.is_empty() {
        if suspended { resume_process(pid); }
        return;
    }

    // Само suspicious процеси
    if !is_suspicious_name(&name) {
        if suspended { resume_process(pid); }
        return;
    }
    println!("🔬 ETW suspicious: {}", name);

    // Вземи cmdline
    let cmdline = process_monitor::get_process_cmdline_pub(pid);

    // Вземи parent name
    let parent_name = get_parent_name(pid);

    // Analyze
    let decision = process_monitor::analyze_process(&name, &cmdline, &parent_name);

    if decision.is_threat {
        println!(
            "🔬 ETW THREAT: {} (PID {}) — {} [{}]",
            name, pid, decision.reason, decision.mitre
        );

        // Kill
        let _ = process_monitor::block_process(pid);
        println!("🚫 ETW BLOCKED: {} (PID {})", name, pid);

        // Record в state
        process_monitor::record_blocked_process(
            pid, &name, &parent_name, &decision.reason,
            &decision.mitre, &decision.severity, true, None
        );
    } else if suspended {
        // Resume ако не е заплаха
        resume_process(pid);
    }
}

fn is_suspicious_name(name: &str) -> bool {
    let n = name.to_lowercase();
    ["powershell", "cmd", "wmic", "mshta", "certutil",
     "regsvr32", "rundll32", "bitsadmin", "wscript", "cscript",
     "mimikatz", "procdump", "pwdump", "reg",
     "net", "wevtutil", "vssadmin", "bcdedit", "sc"].iter().any(|s| n.contains(s))
}

fn get_process_name(pid: u32) -> String {
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return String::new(),
        };
        let mut buf = [0u16; 260];
        let mut size = 260u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, windows::core::PWSTR(buf.as_mut_ptr()), &mut size);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        if ok.is_ok() && size > 0 {
            let full = String::from_utf16_lossy(&buf[..size as usize]);
            full.split('\\').last().unwrap_or("").to_string()
        } else {
            String::new()
        }
    }
}

fn get_parent_name(pid: u32) -> String {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return String::from("unknown"),
        };
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut parent_pid = 0u32;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    parent_pid = entry.th32ParentProcessID;
                    break;
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        if parent_pid == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            return String::from("unknown");
        }

        let mut entry2: PROCESSENTRY32W = std::mem::zeroed();
        entry2.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry2).is_ok() {
            loop {
                if entry2.th32ProcessID == parent_pid {
                    let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                    return String::from_utf16_lossy(
                        &entry2.szExeFile.iter().take_while(|&&c| c != 0).copied().collect::<Vec<u16>>()
                    );
                }
                if Process32NextW(snapshot, &mut entry2).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        String::from("unknown")
    }
}

fn suspend_process(pid: u32) -> bool {
    use windows::Win32::System::Threading::OpenProcess;
    use windows::Win32::System::Threading::PROCESS_SUSPEND_RESUME;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleW};
    use windows::core::s;

    unsafe {
        let ntdll = match GetModuleHandleW(windows::core::w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let func = match GetProcAddress(ntdll, s!("NtSuspendProcess")) {
            Some(f) => f,
            None => return false,
        };

        let handle = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        type NtSuspendProcess = unsafe extern "system" fn(HANDLE) -> i32;
        let nt_suspend: NtSuspendProcess = std::mem::transmute(func);
        let result = nt_suspend(handle);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
        result >= 0
    }
}

fn resume_process(pid: u32) {
    use windows::Win32::System::Threading::OpenProcess;
    use windows::Win32::System::Threading::PROCESS_SUSPEND_RESUME;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleW};
    use windows::core::s;

    unsafe {
        let ntdll = match GetModuleHandleW(windows::core::w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return,
        };

        let func = match GetProcAddress(ntdll, s!("NtResumeProcess")) {
            Some(f) => f,
            None => return,
        };

        let handle = match OpenProcess(PROCESS_SUSPEND_RESUME, false, pid) {
            Ok(h) => h,
            Err(_) => return,
        };

        type NtResumeProcess = unsafe extern "system" fn(HANDLE) -> i32;
        let nt_resume: NtResumeProcess = std::mem::transmute(func);
        let _ = nt_resume(handle);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
}
