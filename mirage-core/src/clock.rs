//! Platform-abstracted clock functions.
//!
//! - `std` feature: uses `std::time::SystemTime` and `std::time::Instant`.
//! - `wasi` feature: uses function pointers set at init by the WATM host.

// ---------------------------------------------------------------------------
// std implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
mod imp {
    use std::sync::OnceLock;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static MONO_ORIGIN: OnceLock<Instant> = OnceLock::new();

    fn origin() -> &'static Instant {
        MONO_ORIGIN.get_or_init(Instant::now)
    }

    pub fn clock_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn clock_nanos() -> u64 {
        origin().elapsed().as_nanos() as u64
    }
}

// ---------------------------------------------------------------------------
// wasi implementation (function-pointer based)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "wasi", not(feature = "std")))]
mod imp {
    use core::sync::atomic::{AtomicPtr, Ordering};

    type ClockFn = fn() -> u64;

    fn default_seconds() -> u64 { 0 }
    fn default_nanos() -> u64 { 0 }

    static CLOCK_SECONDS_FN: AtomicPtr<()> =
        AtomicPtr::new(default_seconds as *mut ());
    static CLOCK_NANOS_FN: AtomicPtr<()> =
        AtomicPtr::new(default_nanos as *mut ());

    /// Register platform clock functions. Must be called before any crypto or
    /// traffic-shaping operations.
    pub fn set_clock_fns(seconds_fn: ClockFn, nanos_fn: ClockFn) {
        CLOCK_SECONDS_FN.store(seconds_fn as *mut (), Ordering::Release);
        CLOCK_NANOS_FN.store(nanos_fn as *mut (), Ordering::Release);
    }

    pub fn clock_seconds() -> u64 {
        let ptr = CLOCK_SECONDS_FN.load(Ordering::Acquire);
        let f: ClockFn = unsafe { core::mem::transmute(ptr) };
        f()
    }

    pub fn clock_nanos() -> u64 {
        let ptr = CLOCK_NANOS_FN.load(Ordering::Acquire);
        let f: ClockFn = unsafe { core::mem::transmute(ptr) };
        f()
    }
}

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

pub use imp::clock_nanos;
pub use imp::clock_seconds;

#[cfg(all(feature = "wasi", not(feature = "std")))]
pub use imp::set_clock_fns;
