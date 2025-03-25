#![no_main]

use std::sync::{LazyLock, Mutex, MutexGuard};

use asan::{
    GuestAddr,
    tracking::{
        Tracking,
        guest::{GuestTracking, GuestTrackingError},
    },
};
use libfuzzer_sys::fuzz_target;
use log::{debug, info};

static INIT_ONCE: LazyLock<Mutex<GuestTracking>> = LazyLock::new(|| {
    env_logger::init();
    Mutex::new(GuestTracking::new().unwrap())
});

fn get_tracking() -> MutexGuard<'static, GuestTracking> {
    INIT_ONCE.lock().unwrap()
}

const MAX_LENGTH: usize = 0x3ff;
/*
 * Deliberately ensure we are short of GuestAddr::MAX so we can use alternative logic for the implementation
 * to check the overlap (which might otherwise overflow). The implementation is tested for overflow in the
 * unit tests
 */
const MAX_ADDR: GuestAddr = 0x7fffffffffff;
const MAX_OFFSET: usize = 0x7ff;

fuzz_target!(|data: Vec<GuestAddr>| {
    let mut tracking = get_tracking();
    if data.len() < 4 {
        return;
    }
    info!("data: {:x?}", data);
    let start = data[0] & MAX_ADDR;
    let len = data[1] & MAX_LENGTH;
    let test_offset = data[2] & MAX_OFFSET;
    let test_len = data[3] & MAX_LENGTH;

    let test_start = if test_offset > MAX_LENGTH {
        start.saturating_add(test_offset - MAX_LENGTH) & MAX_ADDR
    } else {
        start.saturating_sub(test_offset)
    };

    let result = tracking.track(start, len);
    if GuestTracking::is_out_of_bounds(start, len) {
        assert_eq!(
            result,
            Err(GuestTrackingError::AddressRangeOverflow(start, len))
        );
        return;
    } else if len == 0 {
        assert_eq!(result, Err(GuestTrackingError::ZeroLength(start)));
        return;
    } else {
        assert_eq!(result, Ok(()));
    }

    let test_result = tracking.track(test_start, test_len);
    if GuestTracking::is_out_of_bounds(test_start, test_len) {
        assert_eq!(
            test_result,
            Err(GuestTrackingError::AddressRangeOverflow(
                test_start, test_len
            ))
        );
    } else if test_len == 0 {
        assert_eq!(test_result, Err(GuestTrackingError::ZeroLength(test_start)));
    } else {
        let end = start + len;
        let test_end = test_start + test_len;
        let a = test_end <= start;
        let b = test_start >= end;
        let overlaps = !(a || b);
        let mut sorted = Vec::from([start, end, test_start, test_end]);
        sorted.sort();
        debug!(
            "start: {:x}, end: {:x}, test_start: {:x}, test_end: {:x}, sorted: {:x?}, a: {}, b: {}, overlaps: {}",
            start, end, test_start, test_end, sorted, a, b, overlaps,
        );
        if overlaps {
            assert_eq!(
                test_result,
                Err(GuestTrackingError::TrackingConflict(
                    start, len, test_start, test_len
                ))
            );
        } else {
            assert_eq!(test_result, Ok(()));
            assert_eq!(tracking.untrack(test_start), Ok(()));
        }
    }
    assert_eq!(tracking.untrack(start), Ok(()));
});
