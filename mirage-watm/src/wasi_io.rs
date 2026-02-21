//! WASI I/O helpers for the MIRAGE WATM module.
//!
//! All I/O in the WASM module goes through WASI Preview 1 syscalls.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// WASI error codes (subset relevant to MIRAGE).
#[allow(dead_code)]
pub mod errno {
    pub const SUCCESS: u16 = 0;
    pub const BADF: u16 = 8;
    pub const AGAIN: u16 = 6;
    pub const INVAL: u16 = 28;
    pub const IO: u16 = 29;
    pub const TIMEDOUT: u16 = 73;
}

/// WASI clock IDs.
#[allow(dead_code)]
pub mod clockid {
    pub const REALTIME: u32 = 0;
    pub const MONOTONIC: u32 = 1;
}

/// WASI subscription/event types for poll_oneoff.
#[allow(dead_code)]
pub mod eventtype {
    pub const CLOCK: u8 = 0;
    pub const FD_READ: u8 = 1;
    pub const FD_WRITE: u8 = 2;
}

// ---------------------------------------------------------------------------
// Raw WASI FFI declarations
// ---------------------------------------------------------------------------

#[repr(C)]
struct WasiIovec {
    buf: *mut u8,
    buf_len: usize,
}

#[repr(C)]
struct WasiCiovec {
    buf: *const u8,
    buf_len: usize,
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
extern "C" {
    fn fd_read(fd: u32, iovs: *const WasiIovec, iovs_len: u32, nread: *mut u32) -> u16;
    fn fd_write(fd: u32, iovs: *const WasiCiovec, iovs_len: u32, nwritten: *mut u32) -> u16;
    fn fd_close(fd: u32) -> u16;
    fn clock_time_get(id: u32, precision: u64, time: *mut u64) -> u16;
    fn random_get(buf: *mut u8, buf_len: u32) -> u16;
    fn poll_oneoff(
        subscriptions: *const u8,
        events: *mut u8,
        nsubscriptions: u32,
        nevents: *mut u32,
    ) -> u16;
}

// ---------------------------------------------------------------------------
// Custom getrandom implementation for WASI
// ---------------------------------------------------------------------------

use getrandom::register_custom_getrandom;

fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let err = unsafe { random_get(buf.as_mut_ptr(), buf.len() as u32) };
    if err != errno::SUCCESS {
        return Err(getrandom::Error::UNSUPPORTED);
    }
    Ok(())
}

register_custom_getrandom!(custom_getrandom);

// ---------------------------------------------------------------------------
// Safe wrappers
// ---------------------------------------------------------------------------

/// Read up to `buf.len()` bytes from a file descriptor.
pub fn read(fd: u32, buf: &mut [u8]) -> Result<usize, u16> {
    let iov = WasiIovec {
        buf: buf.as_mut_ptr(),
        buf_len: buf.len(),
    };
    let mut nread: u32 = 0;
    let err = unsafe { fd_read(fd, &iov, 1, &mut nread) };
    if err != errno::SUCCESS {
        Err(err)
    } else {
        Ok(nread as usize)
    }
}

/// Read exactly `buf.len()` bytes from a file descriptor.
pub fn read_exact(fd: u32, buf: &mut [u8]) -> Result<(), u16> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = read(fd, &mut buf[offset..])?;
        if n == 0 {
            return Err(errno::IO);
        }
        offset += n;
    }
    Ok(())
}

/// Read all available data from a file descriptor.
pub fn read_all(fd: u32) -> Result<Vec<u8>, u16> {
    let mut result = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match read(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                result.extend_from_slice(&buf[..n]);
                if n < buf.len() {
                    break;
                }
            }
            Err(e) if e == errno::AGAIN => break,
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

/// Write all bytes to a file descriptor.
pub fn write_all(fd: u32, data: &[u8]) -> Result<(), u16> {
    let mut offset = 0;
    while offset < data.len() {
        let iov = WasiCiovec {
            buf: data[offset..].as_ptr(),
            buf_len: data.len() - offset,
        };
        let mut nwritten: u32 = 0;
        let err = unsafe { fd_write(fd, &iov, 1, &mut nwritten) };
        if err != errno::SUCCESS {
            return Err(err);
        }
        offset += nwritten as usize;
        if nwritten == 0 {
            return Err(errno::IO);
        }
    }
    Ok(())
}

/// Close a file descriptor.
#[allow(dead_code)]
pub fn close(fd: u32) -> Result<(), u16> {
    let err = unsafe { fd_close(fd) };
    if err != errno::SUCCESS {
        Err(err)
    } else {
        Ok(())
    }
}

/// Get the current wall-clock time in seconds (Unix timestamp).
pub fn clock_seconds() -> u64 {
    let mut time: u64 = 0;
    let err = unsafe { clock_time_get(clockid::REALTIME, 1_000_000_000, &mut time) };
    if err != errno::SUCCESS {
        0
    } else {
        time / 1_000_000_000
    }
}

/// Get the current monotonic clock time in nanoseconds.
pub fn clock_nanos() -> u64 {
    let mut time: u64 = 0;
    let err = unsafe { clock_time_get(clockid::MONOTONIC, 1, &mut time) };
    if err != errno::SUCCESS {
        0
    } else {
        time
    }
}

/// Poll multiple file descriptors for read readiness with a timeout.
pub fn poll_read_timeout(fds: &[u32], timeout_ns: u64) -> Result<Vec<u32>, u16> {
    const SUB_SIZE: usize = 48;
    const EVENT_SIZE: usize = 32;

    let has_timeout = timeout_ns != u64::MAX;
    let n_subs = fds.len() + if has_timeout { 1 } else { 0 };

    let mut subs = vec![0u8; n_subs * SUB_SIZE];
    let mut events = vec![0u8; n_subs * EVENT_SIZE];
    let mut nevents: u32 = 0;

    for (i, &fd) in fds.iter().enumerate() {
        let base = i * SUB_SIZE;
        let userdata = fd as u64;
        subs[base..base + 8].copy_from_slice(&userdata.to_le_bytes());
        subs[base + 8] = eventtype::FD_READ;
        subs[base + 16..base + 20].copy_from_slice(&fd.to_le_bytes());
    }

    if has_timeout {
        let base = fds.len() * SUB_SIZE;
        subs[base..base + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        subs[base + 8] = eventtype::CLOCK;
        subs[base + 16..base + 20].copy_from_slice(&clockid::MONOTONIC.to_le_bytes());
        subs[base + 24..base + 32].copy_from_slice(&timeout_ns.to_le_bytes());
    }

    let err = unsafe {
        poll_oneoff(
            subs.as_ptr(),
            events.as_mut_ptr(),
            n_subs as u32,
            &mut nevents,
        )
    };

    if err != errno::SUCCESS {
        return Err(err);
    }

    let mut ready = Vec::new();
    for i in 0..nevents as usize {
        let base = i * EVENT_SIZE;
        let mut userdata_bytes = [0u8; 8];
        userdata_bytes.copy_from_slice(&events[base..base + 8]);
        let userdata = u64::from_le_bytes(userdata_bytes);

        if userdata == u64::MAX {
            continue; // Timeout event
        }

        let error = u16::from_le_bytes([events[base + 8], events[base + 9]]);
        if error == errno::SUCCESS {
            ready.push(userdata as u32);
        }
    }

    Ok(ready)
}

/// Poll multiple file descriptors for read readiness (blocking, no timeout).
#[allow(dead_code)]
pub fn poll_read(fds: &[u32]) -> Result<Vec<u32>, u16> {
    poll_read_timeout(fds, u64::MAX)
}
