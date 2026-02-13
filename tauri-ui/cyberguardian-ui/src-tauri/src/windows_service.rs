//! Windows Service Management for CyberGuardian XDR

#![cfg(windows)]

use windows::core::{w, PCWSTR};
use windows::Win32::System::Services::{
    CloseServiceHandle, CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW,
    QueryServiceStatus, StartServiceW, ControlService,
    SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_STATUS,
    SERVICE_WIN32_OWN_PROCESS, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_QUERY_STATUS,
    SERVICE_START, SERVICE_STOP,
};


/// Service configuration
const SERVICE_NAME: PCWSTR = w!("CyberGuardianXDR");
const SERVICE_DISPLAY_NAME: PCWSTR = w!("CyberGuardian XDR Desktop Agent");

/// Install CyberGuardian as a Windows Service
pub fn install_service() -> Result<(), String> {
    println!("🚀 install_service() CALLED - Starting installation...");
    
    unsafe {
        println!("📂 Opening Service Control Manager...");
        
        // Open Service Control Manager
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_ALL_ACCESS,
        ).map_err(|e| {
            let msg = format!("Failed to open Service Control Manager: {:?}", e);
            println!("❌ SCM Error: {}", msg);
            msg
        })?;

        if scm.is_invalid() {
            println!("❌ Invalid SCM handle");
            return Err("Invalid SCM handle".to_string());
        }
        
        println!("✅ SCM opened successfully");

        // Get current executable path
        println!("📍 Getting executable path...");
        let exe_path = std::env::current_exe()
            .map_err(|e| {
                let msg = format!("Failed to get executable path: {}", e);
                println!("❌ {}", msg);
                msg
            })?;
        
        let exe_path_str = exe_path.to_string_lossy().to_string();
        println!("✅ Executable path: {}", exe_path_str);
        
        let mut exe_path_wide: Vec<u16> = exe_path_str.encode_utf16().collect();
        exe_path_wide.push(0); // Null terminator

        println!("🔨 Creating service...");
        
        // Create the service
        let service = CreateServiceW(
            scm,
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR::from_raw(exe_path_wide.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        );

        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) => {
                if !service_handle.is_invalid() {
                    let _ = CloseServiceHandle(service_handle);
                    println!("✅ Service installed successfully: CyberGuardianXDR");
                    Ok(())
                } else {
                    println!("❌ Invalid service handle");
                    Err("Invalid service handle".to_string())
                }
            }
            Err(e) => {
                let msg = format!("Failed to create service: {:?}", e);
                println!("❌ CreateService Error: {}", msg);
                Err(msg)
            }
        }
    }
}

/// Uninstall the service
pub fn uninstall_service() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_ALL_ACCESS,
        ).map_err(|e| format!("Failed to open SCM: {:?}", e))?;

        if scm.is_invalid() {
            return Err("Invalid SCM handle".to_string());
        }

        // Open service with STOP, QUERY, and DELETE permissions
       let service = OpenServiceW(
    scm,
    SERVICE_NAME,
    SERVICE_STOP | SERVICE_QUERY_STATUS | 0x00010000, // DELETE permission
);

        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) => {
                if service_handle.is_invalid() {
                    return Err("Invalid service handle".to_string());
                }

                // Try to stop service first
                let _ = stop_service_internal(service_handle);

                // Delete the service
                let result = DeleteService(service_handle);
                let _ = CloseServiceHandle(service_handle);

                match result {
                    Ok(_) => {
                        println!("✅ Service uninstalled successfully");
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to delete service: {:?}", e))
                }
            }
            Err(e) => {
                Err(format!("Failed to open service: {:?}", e))
            }
        }
    }
}

/// Start the service
pub fn start_service() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ).map_err(|e| format!("Failed to open SCM: {:?}", e))?;

        if scm.is_invalid() {
            return Err("Invalid SCM handle".to_string());
        }

        let service = OpenServiceW(scm, SERVICE_NAME, SERVICE_START);
        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) => {
                if service_handle.is_invalid() {
                    return Err("Invalid service handle".to_string());
                }

                let result = StartServiceW(service_handle, None);
                let _ = CloseServiceHandle(service_handle);

                match result {
                    Ok(_) => {
                        println!("✅ Service started successfully");
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to start service: {:?}", e))
                }
            }
            Err(e) => Err(format!("Failed to open service: {:?}", e))
        }
    }
}

/// Stop the service
pub fn stop_service() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ).map_err(|e| format!("Failed to open SCM: {:?}", e))?;

        if scm.is_invalid() {
            return Err("Invalid SCM handle".to_string());
        }

        let service = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP);
        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) => {
                if service_handle.is_invalid() {
                    return Err("Invalid service handle".to_string());
                }

                let result = stop_service_internal(service_handle);
                let _ = CloseServiceHandle(service_handle);
                result
            }
            Err(e) => Err(format!("Failed to open service: {:?}", e))
        }
    }
}

/// Internal function to stop a service
unsafe fn stop_service_internal(service_handle: windows::Win32::System::Services::SC_HANDLE) -> Result<(), String> {
    let mut status = SERVICE_STATUS::default();
    let result = ControlService(service_handle, SERVICE_CONTROL_STOP, &mut status);

    match result {
        Ok(_) => {
            println!("✅ Service stopped successfully");
            Ok(())
        }
        Err(e) => Err(format!("Failed to stop service: {:?}", e))
    }
}

/// Check if service is installed
pub fn is_service_installed() -> bool {
    unsafe {
        let scm = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ) {
            Ok(handle) if !handle.is_invalid() => handle,
            _ => return false,
        };

        let service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) if !service_handle.is_invalid() => {
                let _ = CloseServiceHandle(service_handle);
                true
            }
            _ => false
        }
    }
}

/// Check if service is running
pub fn is_service_running() -> bool {
    unsafe {
        let scm = match OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT,
        ) {
            Ok(handle) if !handle.is_invalid() => handle,
            _ => return false,
        };

        let service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        let _ = CloseServiceHandle(scm);

        match service {
            Ok(service_handle) if !service_handle.is_invalid() => {
                let mut status = SERVICE_STATUS::default();
                let result = QueryServiceStatus(service_handle, &mut status);
                let _ = CloseServiceHandle(service_handle);

                match result {
                    Ok(_) => status.dwCurrentState == SERVICE_RUNNING,
                    Err(_) => false
                }
            }
            _ => false
        }
    }
}

/// Get service status as string
pub fn get_service_status() -> String {
    if !is_service_installed() {
        return "Not Installed".to_string();
    }

    if is_service_running() {
        "Running".to_string()
    } else {
        "Stopped".to_string()
    }
}