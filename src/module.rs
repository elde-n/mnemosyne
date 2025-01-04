use std::{
    ffi::c_void,
    fs::File,
    io::{BufRead, BufReader, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    ptr::NonNull
};

use nix::{
    sys::{
        mman::{mprotect, ProtFlags},
        uio::{process_vm_readv, process_vm_writev, RemoteIoVec}
    },
    unistd::{sysconf, Pid, SysconfVar}
};

use xxhash_rust::xxh64::xxh64;

pub fn read<T: Copy>(address: u64) -> Option<T> {
    let size = std::mem::size_of::<T>();
    let mut value: MaybeUninit<T> = MaybeUninit::uninit();

    let buffer = unsafe { std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size) };

    let result = process_vm_readv(
        Pid::this(),
        &mut [IoSliceMut::new(buffer)],
        &[RemoteIoVec {
            base: address as usize,
            len: size
        }]
    );

    match result {
        Ok(read_size) if read_size == size => Some(unsafe { value.assume_init() }),
        _ => None
    }
}

pub fn write<T: Copy>(address: u64, value: &T) -> Result<(), String> {
    let size = std::mem::size_of::<T>();

    let buffer = unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size) };

    unsafe {
        let page_size = match sysconf(SysconfVar::PAGE_SIZE) {
            Ok(Some(size)) => size as u64,
            _ => 4096
        };

        let page_aligned_addr = (address & !(page_size - 1)) as *mut c_void;
        let non_null_addr = match NonNull::new(page_aligned_addr) {
            Some(addr) => addr,
            None => {
                return Err(String::from(
                    "failed to create non-null pointer for memory protection"
                ));
            }
        };

        if let Err(error) = mprotect(
            non_null_addr,
            page_size as usize,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC
        ) {
            return Err(format!("failed to set memory protection: {}", error));
        }
    }

    let result = process_vm_writev(
        Pid::this(),
        &[IoSlice::new(buffer)],
        &[RemoteIoVec {
            base: address as usize,
            len: size
        }]
    );

    match result {
        Ok(_) => Ok(()),
        Err(error) => Err(format!("error writing to process memory: {}", error))
    }
}

pub fn bounds<const N: usize>(hash: u64) -> Option<(u64, u64)> {
    let maps = File::open("/proc/self/maps").ok()?;
    let reader = BufReader::new(maps);

    for map in reader.lines() {
        let Some(map) = map.ok() else { continue };

        let Some(dash) = map.find('-') else { continue };

        let Some(space) = map.find(' ') else { continue };

        let Some(end) = map.get((dash + 1)..space) else {
            continue
        };

        let Some(start) = u64::from_str_radix(&map[..dash], 16).ok() else {
            continue
        };

        let Some(end) = u64::from_str_radix(end, 16).ok() else {
            continue
        };

        if ((end - start) as usize) < N {
            continue
        }

        let Some(buffer) = read::<[u8; N]>(start) else {
            continue
        };

        if hash != xxh64(&buffer, 0) {
            continue
        }

        return Some((start, end))
    }

    None
}
