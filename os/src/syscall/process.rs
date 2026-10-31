//! Process management syscalls
use core::{mem::size_of, slice::from_raw_parts};
use crate::{config::PAGE_SIZE, mm::{MapPermission, PageTable, VirtAddr, translated_byte_buffer}, task::{TaskManager, change_program_brk, current_user_token, exit_current_and_run_next, get_syscall_count, suspend_current_and_run_next}, timer::{get_time_ms, get_time_us}};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let ts = TimeVal {
        sec: get_time_ms() / 1000,
        usec: get_time_us() % 1000000,
    };
    let bytes = unsafe {
        from_raw_parts(&ts as *const _ as *const u8, size_of::<TimeVal>())
    };
    let buffers = translated_byte_buffer(current_user_token(), _ts as *const u8, size_of::<TimeVal>());
    let mut cur = 0;
    for b in buffers {
        let end = cur + b.len();
        b.copy_from_slice(&bytes[cur..end]);
        cur = end;
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    if trace_request == 0 {
        let va = VirtAddr::from(id);
        if usize::from(va) != id {
            return -1;
        }
        let pte = PageTable::from_token(current_user_token()).translate(va.floor());
        if let Some(pte) = pte {
            if pte.is_valid() {
                return pte.ppn().get_bytes_array()[va.page_offset()] as isize;
            }
        }
        return -1;
    } else if trace_request == 1 {
        let va = VirtAddr::from(id);
        if usize::from(va) != id {
            return -1;
        }
        let pte = PageTable::from_token(current_user_token()).translate(va.floor());
        if let Some(pte) = pte {
            if pte.is_valid() && pte.writable() {
                pte.ppn().get_bytes_array()[va.page_offset()] = data as u8;
                return 0;
            }
        }
        return -1;
    } else if trace_request == 2 {
        return get_syscall_count(id) as isize;
    }
    -1
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    // port only allows R/W/X bits, and must not be zero
    if port == 0 || port & !0b111 != 0 {
        return -1;
    }
    // start must be page aligned, len is rounded up to page size
    if start % PAGE_SIZE != 0 || len == 0 {
        return -1;
    }
    let len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1); // align to page size
    let Some(end) = start.checked_add(len) else {
        return -1;
    };
    let mut permission = MapPermission::U;
    if port & 1 == 1 {
        permission |= MapPermission::R;
    }
    if port & 2 == 2 {
        permission |= MapPermission::W;
    }
    if port & 4 == 4 {
        permission |= MapPermission::X;
    }
    // 0 on success, -1 if the range overlaps an existing area
    TaskManager::map(start.into(), end.into(), permission)
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    // both start and len must be page aligned, otherwise fail
    if start % PAGE_SIZE != 0 || len == 0 || len % PAGE_SIZE != 0 {
        return -1;
    }
    let Some(end) = start.checked_add(len) else {
        return -1;
    };
    TaskManager::unmap(start.into(), end.into())
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
