//! CyberGuardian AMSI Provider — COM Interface Implementation

#![allow(non_snake_case, non_camel_case_types)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::core::{GUID, HRESULT};
use windows::Win32::Foundation::*;
use windows::Win32::System::Com::*;

static SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);

// AMSI GUIDs
const CLSID_CYBERGUARDIAN: GUID = GUID {
    data1: 0x2781761E,
    data2: 0x28E0,
    data3: 0x4109,
    data4: [0x99, 0xFE, 0xB9, 0xD1, 0x27, 0xC5, 0x7B, 0x01],
};

const IID_IAMSI_PROVIDER: GUID = GUID {
    data1: 0x68B2CB3B,
    data2: 0x0EF5,
    data3: 0x4C37,
    data4: [0x96, 0xF3, 0xEA, 0x3B, 0x52, 0x47, 0x20, 0x2B],
};

const IID_IUNKNOWN: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

// AMSI Result values
const AMSI_RESULT_CLEAN: u32 = 0;
const AMSI_RESULT_BLOCKED_BY_ADMIN_START: u32 = 16384;

// Малварни сигнатури
const MALICIOUS_PATTERNS: &[&str] = &[
    "invoke-mimikatz",
    "sekurlsa::logonpasswords",
    "lsadump::sam",
    "lsadump::dcsync",
    "privilege::debug",
    "mimikatz",
    "amsiutils",
    "amsiinitfailed",
    "invoke-credentialinjection",
    "downloadstring",
    "net.webclient",
    "powersploit",
    "powerup",
    "powerview",
    "invoke-allchecks",
    "shellcode",
    "virtualalloc",
    "invoke-psexec",
    "invoke-wmiexec",
];

fn log(msg: &str) {
    let _ = std::fs::create_dir_all("C:\\ProgramData\\CyberGuardian");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("C:\\ProgramData\\CyberGuardian\\amsi_detections.log")
    {
        use std::io::Write;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs();
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

fn scan_content(content: &str) -> u32 {
    let lower = content.to_lowercase();
    for pattern in MALICIOUS_PATTERNS {
        if lower.contains(pattern) {
            log(&format!("BLOCKED pattern='{}' preview='{}'",
                pattern, &content[..content.len().min(100)]));
            return AMSI_RESULT_BLOCKED_BY_ADMIN_START;
        }
    }
    AMSI_RESULT_CLEAN
}

// ── IAmsiProvider VTable ─────────────────────────────────────────────────

#[repr(C)]
struct IAmsiProviderVtbl {
    // IUnknown
    QueryInterface: unsafe extern "system" fn(*mut AmsiProvider, *const GUID, *mut *mut c_void) -> HRESULT,
    AddRef: unsafe extern "system" fn(*mut AmsiProvider) -> u32,
    Release: unsafe extern "system" fn(*mut AmsiProvider) -> u32,
    // IAmsiProvider
    Scan: unsafe extern "system" fn(*mut AmsiProvider, *mut c_void, *mut u32) -> HRESULT,
    CloseSession: unsafe extern "system" fn(*mut AmsiProvider, *mut c_void) -> HRESULT,
}

#[repr(C)]
struct AmsiProvider {
    vtbl: *const IAmsiProviderVtbl,
    ref_count: AtomicU32,
}

static VTBL: IAmsiProviderVtbl = IAmsiProviderVtbl {
    QueryInterface: amsi_query_interface,
    AddRef: amsi_add_ref,
    Release: amsi_release,
    Scan: amsi_scan,
    CloseSession: amsi_close_session,
};

unsafe extern "system" fn amsi_query_interface(
    this: *mut AmsiProvider,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() { return HRESULT(-2147467261i32); } // E_POINTER
    let riid = &*riid;
    if *riid == IID_IUNKNOWN || *riid == IID_IAMSI_PROVIDER {
        *ppv = this as *mut c_void;
        amsi_add_ref(this);
        HRESULT(0)
    } else {
        *ppv = std::ptr::null_mut();
        HRESULT(-2147467262i32) // E_NOINTERFACE
    }
}

unsafe extern "system" fn amsi_add_ref(this: *mut AmsiProvider) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn amsi_release(this: *mut AmsiProvider) -> u32 {
    let count = (*this).ref_count.fetch_sub(1, Ordering::SeqCst) - 1;
    if count == 0 {
        let _ = Box::from_raw(this);
    }
    count
}

unsafe extern "system" fn amsi_scan(
    _this: *mut AmsiProvider,
    scan: *mut c_void,
    result: *mut u32,
) -> HRESULT {
    if result.is_null() || scan.is_null() {
        return HRESULT(-2147467261i32);
    }

    let vtbl = *(scan as *mut *mut *mut usize);
    
    type FnGetScanContext = unsafe extern "system" fn(
        *mut c_void, u32, u32, *mut u8, *mut u32
    ) -> HRESULT;
    
    let get_scan_context: FnGetScanContext = std::mem::transmute(*vtbl.add(3));

    let mut content_size: u64 = 0;
    let mut ret_size: u32 = 0;
    let hr = get_scan_context(
        scan, 2,
        std::mem::size_of::<u64>() as u32,
        &mut content_size as *mut u64 as *mut u8,
        &mut ret_size,
    );
    if hr.0 != 0 || content_size == 0 {
        *result = AMSI_RESULT_CLEAN;
        return HRESULT(0);
    }

    let mut content_addr: usize = 0;
    let hr = get_scan_context(
        scan, 3,
        std::mem::size_of::<usize>() as u32,
        &mut content_addr as *mut usize as *mut u8,
        &mut ret_size,
    );
    if hr.0 != 0 || content_addr == 0 {
        *result = AMSI_RESULT_CLEAN;
        return HRESULT(0);
    }

    let size = (content_size as usize).min(65536);
    let bytes = std::slice::from_raw_parts(content_addr as *const u8, size);
    
    let content = if size >= 2 && size % 2 == 0 {
        let words = std::slice::from_raw_parts(content_addr as *const u16, size / 2);
        String::from_utf16_lossy(words)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    };

    *result = scan_content(&content);
    HRESULT(0)
}

unsafe extern "system" fn amsi_close_session(
    _this: *mut AmsiProvider,
    _session: *mut c_void,
) -> HRESULT {
    HRESULT(0)
}

// ── IClassFactory ────────────────────────────────────────────────────────

#[repr(C)]
struct ClassFactoryVtbl {
    QueryInterface: unsafe extern "system" fn(*mut ClassFactory, *const GUID, *mut *mut c_void) -> HRESULT,
    AddRef: unsafe extern "system" fn(*mut ClassFactory) -> u32,
    Release: unsafe extern "system" fn(*mut ClassFactory) -> u32,
    CreateInstance: unsafe extern "system" fn(*mut ClassFactory, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    LockServer: unsafe extern "system" fn(*mut ClassFactory, BOOL) -> HRESULT,
}

#[repr(C)]
struct ClassFactory {
    vtbl: *const ClassFactoryVtbl,
    ref_count: AtomicU32,
}

unsafe impl Sync for ClassFactory {}
unsafe impl Send for ClassFactory {}

static CF_VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
    QueryInterface: cf_query_interface,
    AddRef: cf_add_ref,
    Release: cf_release,
    CreateInstance: cf_create_instance,
    LockServer: cf_lock_server,
};

static CLASS_FACTORY: ClassFactory = ClassFactory {
    vtbl: &CF_VTBL,
    ref_count: AtomicU32::new(1),
};

unsafe extern "system" fn cf_query_interface(
    this: *mut ClassFactory,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() { return HRESULT(-2147467261i32); }
    *ppv = this as *mut c_void;
    HRESULT(0)
}

unsafe extern "system" fn cf_add_ref(this: *mut ClassFactory) -> u32 {
    (*this).ref_count.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn cf_release(this: *mut ClassFactory) -> u32 {
    (*this).ref_count.fetch_sub(1, Ordering::SeqCst) - 1
}

unsafe extern "system" fn cf_create_instance(
    _this: *mut ClassFactory,
    _outer: *mut c_void,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() { return HRESULT(-2147467261i32); }

    let provider = Box::new(AmsiProvider {
        vtbl: &VTBL,
        ref_count: AtomicU32::new(1),
    });

    let raw = Box::into_raw(provider);
    *ppv = raw as *mut c_void;
    log("AmsiProvider instance created");
    HRESULT(0)
}

unsafe extern "system" fn cf_lock_server(
    _this: *mut ClassFactory,
    _lock: BOOL,
) -> HRESULT {
    HRESULT(0)
}

// ── DLL Exports ──────────────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn DllMain(
    _hinstance: *mut c_void,
    reason: u32,
    _reserved: *mut c_void,
) -> i32 {
    if reason == 1 {
        let _ = std::fs::create_dir_all("C:\\ProgramData\\CyberGuardian");
        let _ = std::fs::write(
            "C:\\ProgramData\\CyberGuardian\\dll_loaded.txt",
            "CyberGuardian AMSI Provider loaded OK"
        );
        log("DLL attached");
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if ppv.is_null() { return HRESULT(-2147467261i32); }

    if *rclsid == CLSID_CYBERGUARDIAN {
        log("DllGetClassObject called — returning ClassFactory");
        *ppv = &CLASS_FACTORY as *const ClassFactory as *mut c_void;
        HRESULT(0)
    } else {
        HRESULT(-2147221231i32) // CLASS_E_CLASSNOTAVAILABLE
    }
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    HRESULT(1) // S_FALSE — не позволяваме unload
}