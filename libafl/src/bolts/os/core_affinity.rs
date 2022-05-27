//! This crate manages CPU affinities.
//!
//! ## Example
//!
//! This example shows how create a thread for each available processor and pin each thread to its corresponding processor.
//!
//! ```
//! extern crate core_affinity;
//!
//! use std::thread;
//!
//! // Retrieve the IDs of all active CPU cores.
//! let core_ids = core_affinity::get_core_ids().unwrap();
//!
//! // Create a thread for each active CPU core.
//! let handles = core_ids.into_iter().map(|id| {
//!     thread::spawn(move || {
//!         // Pin this thread to a single CPU core.
//!         core_affinity::set_for_current(id);
//!         // Do more work after this.
//!     })
//! }).collect::<Vec<_>>();
//!
//! for handle in handles.into_iter() {
//!     handle.join().unwrap();
//! }
//!
//! *This has been forked from <https://github.com/Elzair/core_affinity_rs>*
//! ```

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

use crate::Error;

/// This function tries to retrieve information
/// on all the "cores" active on this system.
pub fn get_core_ids() -> Result<Vec<CoreId>, Error> {
    get_core_ids_helper()
}

/// This function tries to pin the current
/// thread to the specified core.
///
/// # Arguments
///
/// * `core_id` - `ID` of the core to pin
pub fn set_for_current(core_id: CoreId) {
    set_for_current_helper(core_id);
}

/// This represents a CPU core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreId {
    /// The numerical `id` of a core
    pub id: usize,
}

impl CoreId {
    /// Set the affinity of the current process to this [`CoreId`]
    pub fn set_affinity(&self) {
        set_for_current(*self);
    }
}

impl From<usize> for CoreId {
    fn from(id: usize) -> Self {
        CoreId { id }
    }
}

/// A list of [`CoreId`] to use for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cores {
    /// The original commandline used during parsing
    pub cmdline: String,

    /// Vec of core ids
    pub ids: Vec<CoreId>,
}

#[cfg(feature = "std")]
impl Cores {
    /// Pick all cores
    pub fn all() -> Result<Self, Error> {
        Self::from_cmdline("all")
    }

    /// Parses core binding args from user input.
    /// Returns a Vec of CPU IDs.
    /// * `./fuzzer --cores 1,2-4,6`: clients run in cores `1,2,3,4,6`
    /// * `./fuzzer --cores all`: one client runs on each available core
    pub fn from_cmdline(args: &str) -> Result<Self, Error> {
        let mut cores: Vec<CoreId> = vec![];

        // ./fuzzer --cores all -> one client runs in each available core
        if args == "all" {
            // TODO: is this really correct? Core ID != core number?
            let num_cores = get_core_ids()?.len();
            for x in 0..num_cores {
                cores.push(x.into());
            }
        } else {
            let core_args: Vec<&str> = args.split(',').collect();

            // ./fuzzer --cores 1,2-4,6 -> clients run in cores 1,2,3,4,6
            for csv in core_args {
                let core_range: Vec<&str> = csv.split('-').collect();
                if core_range.len() == 1 {
                    cores.push(core_range[0].parse::<usize>()?.into());
                } else if core_range.len() == 2 {
                    for x in core_range[0].parse::<usize>()?..=(core_range[1].parse::<usize>()?) {
                        cores.push(x.into());
                    }
                }
            }
        }

        if cores.is_empty() {
            return Err(Error::illegal_argument(format!(
                "No cores specified! parsed: {}",
                args
            )));
        }

        Ok(Self {
            cmdline: args.to_string(),
            ids: cores,
        })
    }

    /// Checks if this [`Cores`] instance contains a given ``core_id``
    #[must_use]
    pub fn contains(&self, core_id: usize) -> bool {
        let core_id = CoreId::from(core_id);
        self.ids.contains(&core_id)
    }
}

impl From<&[usize]> for Cores {
    fn from(cores: &[usize]) -> Self {
        let cmdline = cores
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(",");
        let ids = cores.iter().map(|x| (*x).into()).collect();
        Self { cmdline, ids }
    }
}

impl From<Vec<usize>> for Cores {
    fn from(cores: Vec<usize>) -> Self {
        Self::from(cores.as_slice())
    }
}

#[cfg(feature = "std")]
impl TryFrom<&str> for Cores {
    type Error = Error;
    fn try_from(cores: &str) -> Result<Self, Self::Error> {
        Self::from_cmdline(cores)
    }
}

/// Parses core binding args from user input.
/// Returns a Vec of CPU IDs.
/// * `./fuzzer --cores 1,2-4,6`: clients run in cores 1,2,3,4,6
/// * `./fuzzer --cores all`: one client runs on each available core
#[must_use]
#[cfg(feature = "std")]
#[deprecated(since = "0.7.1", note = "Use Cores::from_cmdline instead")]
pub fn parse_core_bind_arg(args: &str) -> Option<Vec<usize>> {
    Cores::from_cmdline(args)
        .ok()
        .map(|cores| cores.ids.iter().map(|x| x.id).collect())
}

// Linux Section

#[cfg(any(target_os = "android", target_os = "linux"))]
#[inline]
fn get_core_ids_helper() -> Option<Vec<CoreId>> {
    linux::get_core_ids()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[inline]
fn set_for_current_helper(core_id: CoreId) {
    linux::set_for_current(core_id);
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux {
    use std::mem;

    use libc::{cpu_set_t, sched_getaffinity, sched_setaffinity, CPU_ISSET, CPU_SET, CPU_SETSIZE};

    use super::CoreId;

    pub fn get_core_ids() -> Option<Vec<CoreId>> {
        if let Some(full_set) = get_affinity_mask() {
            let mut core_ids: Vec<CoreId> = Vec::new();

            for i in 0..CPU_SETSIZE as usize {
                if unsafe { CPU_ISSET(i, &full_set) } {
                    core_ids.push(CoreId { id: i });
                }
            }

            Some(core_ids)
        } else {
            None
        }
    }

    pub fn set_for_current(core_id: CoreId) {
        // Turn `core_id` into a `libc::cpu_set_t` with only
        // one core active.
        let mut set = new_cpu_set();

        unsafe { CPU_SET(core_id.id, &mut set) };

        // Set the current thread's core affinity.
        unsafe {
            sched_setaffinity(
                0, // Defaults to current thread
                mem::size_of::<cpu_set_t>(),
                &set,
            );
        }
    }

    fn get_affinity_mask() -> Option<cpu_set_t> {
        let mut set = new_cpu_set();

        // Try to get current core affinity mask.
        let result = unsafe {
            sched_getaffinity(
                0, // Defaults to current thread
                mem::size_of::<cpu_set_t>(),
                &mut set,
            )
        };

        if result == 0 {
            Some(set)
        } else {
            None
        }
    }

    fn new_cpu_set() -> cpu_set_t {
        unsafe { mem::zeroed::<cpu_set_t>() }
    }

    #[cfg(test)]
    mod tests {
        use num_cpus;

        use super::*;

        #[test]
        fn test_linux_get_affinity_mask() {
            match get_affinity_mask() {
                Some(_) => {}
                None => {
                    assert!(false);
                }
            }
        }

        #[test]
        fn test_linux_get_core_ids() {
            match get_core_ids() {
                Some(set) => {
                    assert_eq!(set.len(), num_cpus::get());
                }
                None => {
                    assert!(false);
                }
            }
        }

        #[test]
        fn test_linux_set_for_current() {
            let ids = get_core_ids().unwrap();

            assert!(ids.len() > 0);

            set_for_current(ids[0]);

            // Ensure that the system pinned the current thread
            // to the specified core.
            let mut core_mask = new_cpu_set();
            unsafe { CPU_SET(ids[0].id, &mut core_mask) };

            let new_mask = get_affinity_mask().unwrap();

            let mut is_equal = true;

            for i in 0..CPU_SETSIZE as usize {
                let is_set1 = unsafe { CPU_ISSET(i, &core_mask) };
                let is_set2 = unsafe { CPU_ISSET(i, &new_mask) };

                if is_set1 != is_set2 {
                    is_equal = false;
                }
            }

            assert!(is_equal);
        }
    }
}

// Windows Section

#[cfg(target_os = "windows")]
#[inline]
fn get_core_ids_helper() -> Option<Vec<CoreId>> {
    windows::get_core_ids()
}

#[cfg(target_os = "windows")]
#[inline]
fn set_for_current_helper(core_id: CoreId) {
    windows::set_for_current(core_id);
}

#[cfg(target_os = "windows")]
extern crate kernel32;
#[cfg(target_os = "windows")]
extern crate winapi;

#[cfg(target_os = "windows")]
mod windows {
    use alloc::string::ToString;
    use kernel32::{
        GetCurrentProcess, GetCurrentThread, GetProcessAffinityMask, SetThreadAffinityMask,
    };
    use winapi::basetsd::{DWORD_PTR, PDWORD_PTR};

    use super::CoreId;

    pub fn get_core_ids() -> Result<Vec<CoreId>, Error> {
        if let Some(mask) = get_affinity_mask() {
            // Find all active cores in the bitmask.
            let mut core_ids: Vec<CoreId> = Vec::new();

            for i in 0..64 as u64 {
                let test_mask = 1 << i;

                if (mask & test_mask) == test_mask {
                    core_ids.push(CoreId { id: i as usize });
                }
            }

            Some(core_ids)
        } else {
            Error::unknown("Illegal affinity mask received".to_string())
        }
    }

    pub fn set_for_current(core_id: CoreId) {
        // Convert `CoreId` back into mask.
        let mask: u64 = 1 << core_id.id;

        // Set core affinity for current thread.
        unsafe {
            SetThreadAffinityMask(GetCurrentThread(), mask as DWORD_PTR);
        }
    }

    fn get_affinity_mask() -> Option<u64> {
        #[cfg(target_pointer_width = "64")]
        let mut process_mask: u64 = 0;
        #[cfg(target_pointer_width = "32")]
        let mut process_mask: u32 = 0;
        #[cfg(target_pointer_width = "64")]
        let mut system_mask: u64 = 0;
        #[cfg(target_pointer_width = "32")]
        let mut system_mask: u32 = 0;

        let res = unsafe {
            GetProcessAffinityMask(
                GetCurrentProcess(),
                &mut process_mask as PDWORD_PTR,
                &mut system_mask as PDWORD_PTR,
            )
        };

        // Successfully retrieved affinity mask
        if res != 0 {
            Some(process_mask as u64)
        }
        // Failed to retrieve affinity mask
        else {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use num_cpus;

        use super::*;

        #[test]
        fn test_macos_get_core_ids() {
            match get_core_ids() {
                Some(set) => {
                    assert_eq!(set.len(), num_cpus::get());
                }
                None => {
                    assert!(false);
                }
            }
        }

        #[test]
        fn test_macos_set_for_current() {
            let ids = get_core_ids().unwrap();

            assert!(ids.len() > 0);

            set_for_current(ids[0]);
        }
    }
}

// MacOS Section

#[cfg(target_os = "macos")]
#[inline]
fn get_core_ids_helper() -> Result<Vec<CoreId>, Error> {
    macos::get_core_ids()
}

#[cfg(target_os = "macos")]
#[inline]
fn set_for_current_helper(core_id: CoreId) {
    macos::set_for_current(core_id);
}

#[cfg(target_os = "macos")]
mod macos {
    use core::ptr::addr_of_mut;

    use crate::Error;

    use super::CoreId;
    use alloc::vec::Vec;
    use libc::{
        integer_t, kern_return_t, mach_msg_type_number_t, pthread_self, thread_policy_flavor_t,
        thread_policy_t, thread_t, THREAD_AFFINITY_POLICY, THREAD_AFFINITY_POLICY_COUNT,
    };
    use num_cpus;

    #[repr(C)]
    struct thread_affinity_policy_data_t {
        affinity_tag: integer_t,
    }

    #[link(name = "System", kind = "framework")]
    extern "C" {
        fn thread_policy_set(
            thread: thread_t,
            flavor: thread_policy_flavor_t,
            policy_info: thread_policy_t,
            count: mach_msg_type_number_t,
        ) -> kern_return_t;
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn get_core_ids() -> Result<Vec<CoreId>, Error> {
        Ok((0..(num_cpus::get()))
            .into_iter()
            .map(|n| CoreId { id: n })
            .collect::<Vec<_>>())
    }

    pub fn set_for_current(core_id: CoreId) {
        let mut info = thread_affinity_policy_data_t {
            affinity_tag: core_id.id.try_into().unwrap(),
        };

        unsafe {
            thread_policy_set(
                pthread_self() as thread_t,
                THREAD_AFFINITY_POLICY as _,
                addr_of_mut!(info) as thread_policy_t,
                THREAD_AFFINITY_POLICY_COUNT,
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use num_cpus;

        use super::*;

        #[test]
        fn test_windows_get_core_ids() {
            match get_core_ids() {
                Ok(set) => {
                    assert_eq!(set.len(), num_cpus::get());
                }
                Err(err) => {
                    panic!("Failed to get core ids: {}", err);
                }
            }
        }

        #[test]
        fn test_windows_set_for_current() {
            let ids = get_core_ids().unwrap();

            assert!(!ids.is_empty());

            set_for_current(ids[0]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_num_cpus() {
    //     println!("Num CPUs: {}", num_cpus::get());
    //     println!("Num Physical CPUs: {}", num_cpus::get_physical());
    // }

    #[test]
    fn test_get_core_ids() {
        let set = get_core_ids().unwrap();
        assert_eq!(set.len(), num_cpus::get());
    }

    #[test]
    fn test_set_for_current() {
        let ids = get_core_ids().unwrap();

        assert!(!ids.is_empty());

        set_for_current(ids[0]);
    }
}
