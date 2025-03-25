#[cfg(test)]
#[cfg(feature = "guest")]
mod tests {

    use std::sync::Mutex;

    use asan::{
        GuestAddr,
        tracking::{
            Tracking,
            guest::{GuestTracking, GuestTrackingError},
        },
    };
    use spin::Lazy;

    static INIT_ONCE: Lazy<Mutex<()>> = Lazy::new(|| {
        {
            env_logger::init();
        };
        Mutex::new(())
    });

    fn get_tracking() -> GuestTracking {
        drop(INIT_ONCE.lock().unwrap());
        GuestTracking::new().unwrap()
    }

    #[test]
    fn test_max() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(GuestAddr::MAX, 1), Ok(()));
    }

    #[test]
    fn test_out_of_bounds() {
        let mut tracking = get_tracking();
        assert_eq!(
            tracking.track(GuestAddr::MAX, 2),
            Err(GuestTrackingError::AddressRangeOverflow(GuestAddr::MAX, 2))
        );
    }

    #[test]
    fn test_track_identical() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(0x1000, 0x1000), Ok(()));
        assert_eq!(
            tracking.track(0x1000, 0x1000),
            Err(GuestTrackingError::TrackingConflict(
                0x1000, 0x1000, 0x1000, 0x1000
            ))
        );
    }

    #[test]
    fn test_track_adjacent_after() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(0x1000, 0x1000), Ok(()));
        assert_eq!(tracking.track(0x2000, 0x1000), Ok(()));
    }

    #[test]
    fn test_track_adjacent_before() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(0x1000, 0x1000), Ok(()));
        assert_eq!(tracking.track(0x0000, 0x1000), Ok(()));
    }

    #[test]
    fn test_track_overlapping_start() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(0x1000, 0x1000), Ok(()));
        assert_eq!(
            tracking.track(0x0000, 0x1001),
            Err(GuestTrackingError::TrackingConflict(
                0x1000, 0x1000, 0x0000, 0x1001
            ))
        );
    }

    #[test]
    fn test_track_overlapping_end() {
        let mut tracking = get_tracking();
        assert_eq!(tracking.track(0x1000, 0x1000), Ok(()));
        assert_eq!(
            tracking.track(0x1fff, 0x1001),
            Err(GuestTrackingError::TrackingConflict(
                0x1000, 0x1000, 0x1fff, 0x1001
            ))
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_example_1() {
        let mut tracking = get_tracking();
        // alloc - start: 0xffffffffb5b5ff21, len: 0x3ff
        // alloc - start: 0xffffffffb5b60107, len: 0xdb
        assert_eq!(tracking.track(0xffffffffb5b5ff21, 0x3ff), Ok(()));
        assert_eq!(
            tracking.track(0xffffffffb5b60107, 0xdb),
            Err(GuestTrackingError::TrackingConflict(
                0xffffffffb5b5ff21,
                0x3ff,
                0xffffffffb5b60107,
                0xdb
            ))
        );
    }
}
