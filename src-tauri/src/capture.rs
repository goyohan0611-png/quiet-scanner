use libloading::Library;
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    path::PathBuf,
};

#[repr(C)]
struct Header {
    seconds: i32,
    microseconds: i32,
    caplen: u32,
    len: u32,
}
#[repr(C)]
struct Program {
    len: u32,
    insns: *mut c_void,
}
type Open = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void);
type Next = unsafe extern "C" fn(*mut c_void, *mut *const Header, *mut *const u8) -> c_int;
type Send = unsafe extern "C" fn(*mut c_void, *const u8, c_int) -> c_int;
type Error = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type Nonblock = unsafe extern "C" fn(*mut c_void, c_int, *mut c_char) -> c_int;
type Compile = unsafe extern "C" fn(*mut c_void, *mut Program, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(*mut c_void, *mut Program) -> c_int;
type Free = unsafe extern "C" fn(*mut Program);
type Datalink = unsafe extern "C" fn(*mut c_void) -> c_int;
pub struct Capture {
    handle: *mut c_void,
    next: Next,
    send: Send,
    error: Error,
    close: Close,
    _library: Library,
}
fn library() -> Result<Library, String> {
    let mut buffer = [0u16; 512];
    let n = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if n == 0 || n >= buffer.len() {
        return Err("Windows 시스템 폴더를 확인하지 못했습니다.".into());
    }
    let sys = PathBuf::from(String::from_utf16_lossy(&buffer[..n]));
    for path in [sys.join("Npcap").join("wpcap.dll"), sys.join("wpcap.dll")] {
        if path.is_file() {
            let loaded =
                unsafe { libloading::os::windows::Library::load_with_flags(path, 0x100 | 0x800) };
            if let Ok(lib) = loaded {
                return Ok(lib.into());
            }
        }
    }
    Err(
        "Npcap을 불러오지 못했습니다. Npcap 설치 시 WinPcap API-compatible mode를 선택하십시오."
            .into(),
    )
}
pub fn available() -> Result<(), String> {
    let _ = library()?;
    Ok(())
}
impl Capture {
    pub fn open(iface: &str, filter: &str) -> Result<Self, String> {
        let lib = library()?;
        let symbol = |e: libloading::Error| format!("Npcap 함수 확인 실패: {e}");
        unsafe {
            let open: Open = *lib.get(b"pcap_open_live\0").map_err(symbol)?;
            let close: Close = *lib.get(b"pcap_close\0").map_err(symbol)?;
            let next: Next = *lib.get(b"pcap_next_ex\0").map_err(symbol)?;
            let send: Send = *lib.get(b"pcap_sendpacket\0").map_err(symbol)?;
            let error: Error = *lib.get(b"pcap_geterr\0").map_err(symbol)?;
            let nonblock: Nonblock = *lib.get(b"pcap_setnonblock\0").map_err(symbol)?;
            let compile: Compile = *lib.get(b"pcap_compile\0").map_err(symbol)?;
            let set: SetFilter = *lib.get(b"pcap_setfilter\0").map_err(symbol)?;
            let free: Free = *lib.get(b"pcap_freecode\0").map_err(symbol)?;
            let datalink: Datalink = *lib.get(b"pcap_datalink\0").map_err(symbol)?;
            let name = CString::new(iface).map_err(|e| e.to_string())?;
            let mut err = [0i8; 256];
            let handle = open(name.as_ptr(), 65535, 0, 5, err.as_mut_ptr());
            if handle.is_null() {
                return Err(format!(
                    "인터페이스 캡처를 열지 못했습니다: {}",
                    CStr::from_ptr(err.as_ptr()).to_string_lossy()
                ));
            }
            let cap = Self {
                handle,
                next,
                send,
                error,
                close,
                _library: lib,
            };
            if datalink(handle) != 1 {
                return Err("Ethernet 프레임 캡처를 지원하지 않는 인터페이스입니다.".into());
            }
            if nonblock(handle, 1, err.as_mut_ptr()) != 0 {
                return Err(cap.error());
            }
            if let Ok(set_min) = cap
                ._library
                .get::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(b"pcap_setmintocopy\0")
            {
                set_min(handle, 0);
            }
            let filter = CString::new(filter).map_err(|e| e.to_string())?;
            let mut program = Program {
                len: 0,
                insns: std::ptr::null_mut(),
            };
            if compile(handle, &mut program, filter.as_ptr(), 1, u32::MAX) != 0 {
                return Err(cap.error());
            }
            let status = set(handle, &mut program);
            free(&mut program);
            if status != 0 {
                return Err(cap.error());
            }
            Ok(cap)
        }
    }
    fn error(&self) -> String {
        unsafe {
            let ptr = (self.error)(self.handle);
            if ptr.is_null() {
                "Npcap 캡처 오류".into()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }
    pub fn send(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() > 65535 {
            return Err("패킷이 너무 큽니다.".into());
        }
        if unsafe { (self.send)(self.handle, packet.as_ptr(), packet.len() as i32) } == 0 {
            Ok(())
        } else {
            Err(self.error())
        }
    }
    pub fn next(&self) -> Result<Option<Vec<u8>>, String> {
        let mut h = std::ptr::null();
        let mut p = std::ptr::null();
        match unsafe { (self.next)(self.handle, &mut h, &mut p) } {
            0 => Ok(None),
            1 => {
                if h.is_null() || p.is_null() {
                    return Err("Npcap 패킷 포인터가 비어 있습니다.".into());
                }
                let len = unsafe { (*h).caplen } as usize;
                if len > 65535 {
                    return Err("Npcap 패킷 길이가 잘못됐습니다.".into());
                }
                Ok(Some(unsafe { std::slice::from_raw_parts(p, len) }.to_vec()))
            }
            _ => Err(self.error()),
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { (self.close)(self.handle) }
    }
}
