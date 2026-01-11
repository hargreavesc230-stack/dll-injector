#[cfg(windows)]
use clap::Parser;

#[cfg(windows)]
mod injector {
    use clap::Parser;
    use std::ffi::OsStr;
    use std::io::{self, Write};
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx,
    };
    use windows_sys::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    #[derive(Parser, Debug)]
    #[command(
        name = "dll-injector",
        about = "Inject a DLL into a target process you own or are authorized to test."
    )]
    pub struct Args {
        /// Path to the DLL to inject
        #[arg(long)]
        pub dll: PathBuf,
    }

    struct ProcessInfo {
        pid: u32,
        name: String,
    }

    fn to_wide_os(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(once(0)).collect()
    }

    fn to_wide_str(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    fn last_error() -> std::io::Error {
        let code = unsafe { GetLastError() } as i32;
        std::io::Error::from_raw_os_error(code)
    }

    fn wide_cstr_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn list_injectable_processes(access: u32) -> Result<Vec<ProcessInfo>, String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("CreateToolhelp32Snapshot failed: {}", last_error()));
        }

        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut processes = Vec::new();
        let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
        if ok == 0 {
            unsafe {
                CloseHandle(snapshot);
            }
            return Err(format!("Process32FirstW failed: {}", last_error()));
        }

        while ok != 0 {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                let handle = unsafe { OpenProcess(access, 0, pid) };
                if handle != 0 {
                    let name = wide_cstr_to_string(&entry.szExeFile);
                    processes.push(ProcessInfo { pid, name });
                    unsafe {
                        CloseHandle(handle);
                    }
                }
            }
            ok = unsafe { Process32NextW(snapshot, &mut entry) };
        }

        unsafe {
            CloseHandle(snapshot);
        }

        processes.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.pid.cmp(&b.pid))
        });

        Ok(processes)
    }

    fn prompt_for_pid(processes: &[ProcessInfo]) -> Result<u32, String> {
        if processes.is_empty() {
            return Err("No injectable processes found.".to_string());
        }

        println!("Available processes you can inject into:");
        for process in processes {
            println!("  {} - {}", process.pid, process.name);
        }

        print!("Enter PID to inject into: ");
        io::stdout()
            .flush()
            .map_err(|e| format!("Failed to flush stdout: {e}"))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {e}"))?;
        let pid: u32 = input
            .trim()
            .parse()
            .map_err(|_| "Invalid PID entered.".to_string())?;

        if processes.iter().any(|p| p.pid == pid) {
            Ok(pid)
        } else {
            Err("PID not found in the list.".to_string())
        }
    }

    pub fn run(args: Args) -> Result<(), String> {
        let dll_path = std::fs::canonicalize(&args.dll)
            .map_err(|e| format!("Failed to resolve DLL path: {e}"))?;
        if !dll_path.is_file() {
            return Err("DLL path does not point to a file.".to_string());
        }

        let dll_wide = to_wide_os(dll_path.as_os_str());
        let dll_bytes = dll_wide.len() * std::mem::size_of::<u16>();

        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;

        let processes = list_injectable_processes(access)?;
        let target_pid = prompt_for_pid(&processes)?;

        let process = unsafe { OpenProcess(access, 0, target_pid) };
        if process == 0 {
            return Err(format!("OpenProcess failed: {}", last_error()));
        }

        let remote_mem = unsafe {
            VirtualAllocEx(
                process,
                null_mut(),
                dll_bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            unsafe {
                CloseHandle(process);
            }
            return Err(format!("VirtualAllocEx failed: {}", last_error()));
        }

        let mut bytes_written: usize = 0;
        let write_ok = unsafe {
            WriteProcessMemory(
                process,
                remote_mem,
                dll_wide.as_ptr() as _,
                dll_bytes,
                &mut bytes_written,
            )
        };
        if write_ok == 0 || bytes_written != dll_bytes {
            unsafe {
                CloseHandle(process);
            }
            return Err(format!("WriteProcessMemory failed: {}", last_error()));
        }

        let kernel32 = unsafe { GetModuleHandleW(to_wide_str("kernel32.dll").as_ptr()) };
        if kernel32 == 0 {
            unsafe {
                CloseHandle(process);
            }
            return Err(format!("GetModuleHandleW failed: {}", last_error()));
        }

        let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr() as _) };
        let load_library = load_library.ok_or_else(|| {
            unsafe {
                CloseHandle(process);
            }
            format!("GetProcAddress failed: {}", last_error())
        })?;

        let thread = unsafe {
            CreateRemoteThread(
                process,
                null_mut(),
                0,
                Some(std::mem::transmute(load_library)),
                remote_mem,
                0,
                null_mut(),
            )
        };
        if thread == 0 {
            unsafe {
                CloseHandle(process);
            }
            return Err(format!("CreateRemoteThread failed: {}", last_error()));
        }

        unsafe {
            CloseHandle(thread);
            CloseHandle(process);
        }

        println!(
            "Injected {} into process {}.",
            dll_path.display(),
            target_pid
        );
        Ok(())
    }
}

#[cfg(windows)]
fn main() {
    let args = injector::Args::parse();
    if let Err(err) = injector::run(args) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This tool only supports Windows.");
    std::process::exit(1);
}
