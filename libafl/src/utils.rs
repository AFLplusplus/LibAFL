//! Utility functions for AFL

use crate::Error;

#[cfg(feature = "std")]
use crate::{
    bolts::shmem::ShMemProvider,
    events::llmp::{LlmpRestartingEventManager, ManagerKind},
    inputs::Input,
    state::IfInteresting,
    stats::Stats,
};

use alloc::vec::Vec;
use core::{cell::RefCell, debug_assert, fmt::Debug, time};
use xxhash_rust::xxh3::xxh3_64_with_seed;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::events::llmp::RestartingMgr;

#[cfg(unix)]
use libc::pid_t;

#[cfg(feature = "std")]
use std::{
    env,
    net::SocketAddr,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(all(unix, feature = "std"))]
use std::{ffi::CString, fs::File, os::unix::io::AsRawFd};

#[cfg(all(windows, feature = "std"))]
use core_affinity::CoreId;

#[cfg(all(windows, feature = "std"))]
use std::process::Stdio;

use typed_builder::TypedBuilder;

/// Can be converted to a slice
pub trait AsSlice<T> {
    /// Convert to a slice
    fn as_slice(&self) -> &[T];
}

/// The standard rand implementation for `LibAFL`.
/// It is usually the right choice, with very good speed and a reasonable randomness.
/// Not cryptographically secure (which is not what you want during fuzzing ;) )
pub type StdRand = RomuTrioRand;

/// Ways to get random around here
/// Please note that these are not cryptographically secure
/// Or, even if some might be by accident, at least they are not seeded in a cryptographically secure fashion.
pub trait Rand: Debug + Serialize + DeserializeOwned {
    /// Sets the seed of this Rand
    fn set_seed(&mut self, seed: u64);

    /// Gets the next 64 bit value
    fn next(&mut self) -> u64;

    /// Gets a value below the given 64 bit val (inclusive)
    fn below(&mut self, upper_bound_excl: u64) -> u64 {
        if upper_bound_excl <= 1 {
            return 0;
        }

        /*
        Modulo is biased - we don't want our fuzzing to be biased so let's do it
        right. See
        https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
        */
        let mut unbiased_rnd: u64;
        loop {
            unbiased_rnd = self.next();
            if unbiased_rnd < (u64::MAX - (u64::MAX % upper_bound_excl)) {
                break;
            }
        }

        unbiased_rnd % upper_bound_excl
    }

    /// Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        debug_assert!(lower_bound_incl <= upper_bound_incl);
        lower_bound_incl + self.below(upper_bound_incl - lower_bound_incl + 1)
    }
}

/// Has a Rand field, that can be used to get random values
pub trait HasRand<R>
where
    R: Rand,
{
    /// Get the hold [`RefCell`] Rand instance
    fn rand(&self) -> &RefCell<R>;

    /// Gets the next 64 bit value
    fn rand_next(&mut self) -> u64 {
        self.rand().borrow_mut().next()
    }
    /// Gets a value below the given 64 bit val (inclusive)
    fn rand_below(&mut self, upper_bound_excl: u64) -> u64 {
        self.rand().borrow_mut().below(upper_bound_excl)
    }

    /// Gets a value between the given lower bound (inclusive) and upper bound (inclusive)
    fn rand_between(&mut self, lower_bound_incl: u64, upper_bound_incl: u64) -> u64 {
        self.rand()
            .borrow_mut()
            .between(lower_bound_incl, upper_bound_incl)
    }
}

// helper macro for deriving Default
macro_rules! default_rand {
    ($rand: ty) => {
        /// A default RNG will usually produce a nondeterministic stream of random numbers.
        /// As we do not have any way to get random seeds for `no_std`, they have to be reproducible there.
        /// Use [`$rand::with_seed`] to generate a reproducible RNG.
        impl core::default::Default for $rand {
            #[cfg(feature = "std")]
            fn default() -> Self {
                Self::new()
            }
            #[cfg(not(feature = "std"))]
            fn default() -> Self {
                Self::with_seed(0xAF1)
            }
        }
    };
}

// Derive Default by calling `new(DEFAULT_SEED)` on each of the following Rand types.
default_rand!(Xoshiro256StarRand);
default_rand!(XorShift64Rand);
default_rand!(Lehmer64Rand);
default_rand!(RomuTrioRand);
default_rand!(RomuDuoJrRand);

/// Initialize Rand types from a source of randomness.
///
/// Default implementations are provided with the "std" feature enabled, using system time in
/// nanoseconds as the initial seed.
pub trait RandomSeed: Rand + Default {
    /// Creates a new [`RandomSeed`].
    fn new() -> Self;
}

// helper macro to impl RandomSeed
macro_rules! impl_randomseed {
    ($rand: ty) => {
        #[cfg(feature = "std")]
        impl RandomSeed for $rand {
            /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
            fn new() -> Self {
                Self::with_seed(current_nanos())
            }
        }
    };
}

impl_randomseed!(Xoshiro256StarRand);
impl_randomseed!(XorShift64Rand);
impl_randomseed!(Lehmer64Rand);
impl_randomseed!(RomuTrioRand);
impl_randomseed!(RomuDuoJrRand);

const HASH_CONST: u64 = 0xa5b35705;

/// Current time
#[cfg(feature = "std")]
#[must_use]
#[inline]
pub fn current_time() -> time::Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// Current time (fixed fallback for no_std)
#[cfg(not(feature = "std"))]
#[inline]
pub fn current_time() -> time::Duration {
    // We may not have a rt clock available.
    // TODO: Make it somehow plugin-able
    time::Duration::from_millis(1)
}

/// Gets current nanoseconds since [`UNIX_EPOCH`]
#[must_use]
#[inline]
pub fn current_nanos() -> u64 {
    current_time().as_nanos() as u64
}

/// Gets current milliseconds since [`UNIX_EPOCH`]
#[must_use]
#[inline]
pub fn current_milliseconds() -> u64 {
    current_time().as_millis() as u64
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Xoshiro256StarRand {
    rand_seed: [u64; 4],
}

impl Rand for Xoshiro256StarRand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed[0] = xxh3_64_with_seed(&HASH_CONST.to_le_bytes(), seed);
        self.rand_seed[1] = self.rand_seed[0] ^ 0x1234567890abcdef;
        self.rand_seed[2] = self.rand_seed[0] & 0x0123456789abcdef;
        self.rand_seed[3] = self.rand_seed[0] | 0x01abcde43f567908;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let ret: u64 = self.rand_seed[0]
            .wrapping_add(self.rand_seed[3])
            .rotate_left(23)
            .wrapping_add(self.rand_seed[0]);
        let t: u64 = self.rand_seed[1] << 17;

        self.rand_seed[2] ^= self.rand_seed[0];
        self.rand_seed[3] ^= self.rand_seed[1];
        self.rand_seed[1] ^= self.rand_seed[2];
        self.rand_seed[0] ^= self.rand_seed[3];

        self.rand_seed[2] ^= t;

        self.rand_seed[3] = self.rand_seed[3].rotate_left(45);

        ret
    }
}

impl Xoshiro256StarRand {
    /// Creates a new Xoshiro rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self { rand_seed: [0; 4] };
        rand.set_seed(seed); // TODO: Proper random seed?
        rand
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct XorShift64Rand {
    rand_seed: u64,
}

impl Rand for XorShift64Rand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = seed ^ 0x1234567890abcdef;
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.rand_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rand_seed = x;
        x
    }
}

impl XorShift64Rand {
    /// Creates a new Xoshiro rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { rand_seed: 0 };
        ret.set_seed(seed); // TODO: Proper random seed?
        ret
    }
}

/// XXH3 Based, hopefully speedy, rnd implementation
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Lehmer64Rand {
    rand_seed: u128,
}

impl Rand for Lehmer64Rand {
    #[allow(clippy::unreadable_literal)]
    fn set_seed(&mut self, seed: u64) {
        self.rand_seed = u128::from(seed) ^ 0x1234567890abcdef;
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        self.rand_seed *= 0xda942042e4dd58b5;
        (self.rand_seed >> 64) as u64
    }
}

impl Lehmer64Rand {
    /// Creates a new Lehmer rand with the given seed
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut ret: Self = Self { rand_seed: 0 };
        ret.set_seed(seed);
        ret
    }
}

/// Extremely quick rand implementation
/// see <https://arxiv.org/pdf/2002.11331.pdf>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuTrioRand {
    x_state: u64,
    y_state: u64,
    z_state: u64,
}

impl RomuTrioRand {
    /// Creates a new `RomuTrioRand` with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self {
            x_state: 0,
            y_state: 0,
            z_state: 0,
        };
        rand.set_seed(seed);
        rand
    }
}

impl Rand for RomuTrioRand {
    fn set_seed(&mut self, seed: u64) {
        self.x_state = seed ^ 0x12345;
        self.y_state = seed ^ 0x6789A;
        self.z_state = seed ^ 0xBCDEF;
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        let yp = self.y_state;
        let zp = self.z_state;
        self.x_state = 15241094284759029579u64.wrapping_mul(zp);
        self.y_state = yp.wrapping_sub(xp).rotate_left(12);
        self.z_state = zp.wrapping_sub(yp).rotate_left(44);
        xp
    }
}

/// see <https://arxiv.org/pdf/2002.11331.pdf>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuDuoJrRand {
    x_state: u64,
    y_state: u64,
}

impl RomuDuoJrRand {
    /// Creates a new `RomuDuoJrRand` with the given seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        let mut rand = Self {
            x_state: 0,
            y_state: 0,
        };
        rand.set_seed(seed);
        rand
    }
}

impl Rand for RomuDuoJrRand {
    fn set_seed(&mut self, seed: u64) {
        self.x_state = seed ^ 0x12345;
        self.y_state = seed ^ 0x6789A;
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn next(&mut self) -> u64 {
        let xp = self.x_state;
        self.x_state = 15241094284759029579u64.wrapping_mul(self.y_state);
        self.y_state = self.y_state.wrapping_sub(xp).rotate_left(27);
        xp
    }
}

/// fake rand, for testing purposes
#[cfg(test)]
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct XkcdRand {
    val: u64,
}

#[cfg(test)]
impl Rand for XkcdRand {
    fn set_seed(&mut self, val: u64) {
        self.val = val
    }

    fn next(&mut self) -> u64 {
        self.val
    }
}

/// A test rng that will return the same value (chose by fair dice roll) for testing.
#[cfg(test)]
impl XkcdRand {
    /// Creates a new [`XkCDRand`] with the rand of 4, [chosen by fair dice roll, guaranteed to be random](https://xkcd.com/221/).
    /// Will always return this seed.
    #[must_use]
    pub fn new() -> Self {
        Self::with_seed(4)
    }

    /// Creates a new [`XkcdRand`] with the given seed. Will always return this seed.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self { val: seed }
    }
}

/// Child Process Handle
#[cfg(unix)]
pub struct ChildHandle {
    pid: pid_t,
}

#[cfg(unix)]
impl ChildHandle {
    /// Block until the child exited and the status code becomes available
    #[must_use]
    pub fn status(&self) -> i32 {
        let mut status = -1;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        status
    }
}

/// The `ForkResult` (result of a fork)
#[cfg(unix)]
pub enum ForkResult {
    /// The fork finished, we are the parent process.
    /// The child has the handle `ChildHandle`.
    Parent(ChildHandle),
    /// The fork finished, we are the child process.
    Child,
}

/// Unix has forks.
/// # Safety
/// A Normal fork. Runs on in two processes. Should be memory safe in general.
#[cfg(unix)]
pub unsafe fn fork() -> Result<ForkResult, Error> {
    match libc::fork() {
        pid if pid > 0 => Ok(ForkResult::Parent(ChildHandle { pid })),
        pid if pid < 0 => {
            // Getting errno from rust is hard, we'll just let the libc print to stderr for now.
            // In any case, this should usually not happen.
            #[cfg(feature = "std")]
            {
                let err_str = CString::new("Fork failed").unwrap();
                libc::perror(err_str.as_ptr());
            }
            Err(Error::Unknown(format!("Fork failed ({})", pid)))
        }
        _ => Ok(ForkResult::Child),
    }
}

/// Executes the current process from the beginning, as subprocess.
/// use `start_self.status()?` to wait for the child
#[cfg(feature = "std")]
pub fn startable_self() -> Result<Command, Error> {
    let mut startable = Command::new(env::current_exe()?);
    startable
        .current_dir(env::current_dir()?)
        .args(env::args().skip(1));
    Ok(startable)
}

/// Allows one to walk the mappings in /proc/self/maps, caling a callback function for each
/// mapping.
/// If the callback returns true, we stop the walk.
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
pub fn walk_self_maps(visitor: &mut dyn FnMut(usize, usize, String, String) -> bool) {
    use regex::Regex;
    use std::io::{BufRead, BufReader};
    let re = Regex::new(r"^(?P<start>[0-9a-f]{8,16})-(?P<end>[0-9a-f]{8,16}) (?P<perm>[-rwxp]{4}) (?P<offset>[0-9a-f]{8}) [0-9a-f]+:[0-9a-f]+ [0-9]+\s+(?P<path>.*)$")
        .unwrap();

    let mapsfile = File::open("/proc/self/maps").expect("Unable to open /proc/self/maps");

    for line in BufReader::new(mapsfile).lines() {
        let line = line.unwrap();
        if let Some(caps) = re.captures(&line) {
            if visitor(
                usize::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap(),
                usize::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap(),
                caps.name("perm").unwrap().as_str().to_string(),
                caps.name("path").unwrap().as_str().to_string(),
            ) {
                break;
            };
        }
    }
}

/// Get the start and end address, permissions and path of the mapping containing a particular address
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
pub fn find_mapping_for_address(address: usize) -> Result<(usize, usize, String, String), Error> {
    let mut result = (0, 0, "".to_string(), "".to_string());
    walk_self_maps(&mut |start, end, permissions, path| {
        if start <= address && address < end {
            result = (start, end, permissions, path);
            true
        } else {
            false
        }
    });

    if result.0 == 0 {
        Err(Error::Unknown(
            "Couldn't find a mapping for this address".to_string(),
        ))
    } else {
        Ok(result)
    }
}

/// Get the start and end address of the mapping containing with a particular path
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
#[must_use]
pub fn find_mapping_for_path(libpath: &str) -> (usize, usize) {
    let mut libstart = 0;
    let mut libend = 0;
    walk_self_maps(&mut |start, end, _permissions, path| {
        if libpath == path {
            if libstart == 0 {
                libstart = start;
            }

            libend = end;
        }
        false
    });

    (libstart, libend)
}

#[cfg(test)]
mod tests {
    //use xxhash_rust::xxh3::xxh3_64_with_seed;

    use crate::utils::{
        Rand, RomuDuoJrRand, RomuTrioRand, StdRand, XorShift64Rand, Xoshiro256StarRand,
    };

    fn test_single_rand<R: Rand>(rand: &mut R) {
        assert_ne!(rand.next(), rand.next());
        assert!(rand.below(100) < 100);
        assert_eq!(rand.below(1), 0);
        assert_eq!(rand.between(10, 10), 10);
        assert!(rand.between(11, 20) > 10);
    }

    #[test]
    fn test_rands() {
        // see cargo bench for speed comparisons
        test_single_rand(&mut StdRand::with_seed(0));
        test_single_rand(&mut RomuTrioRand::with_seed(0));
        test_single_rand(&mut RomuDuoJrRand::with_seed(0));
        test_single_rand(&mut XorShift64Rand::with_seed(0));
        test_single_rand(&mut Xoshiro256StarRand::with_seed(0));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_random_seed() {
        use crate::utils::RandomSeed;

        let mut rand_fixed = StdRand::with_seed(0);
        let mut rand = StdRand::new();

        // The seed should be reasonably random so these never fail
        assert_ne!(rand.next(), rand_fixed.next());
        test_single_rand(&mut rand);
    }
}

/// Provides a Launcher, which can be used to launch a fuzzing run on a specified list of cores
#[cfg(feature = "std")]
#[derive(TypedBuilder)]
#[allow(clippy::type_complexity)]
pub struct Launcher<'a, I, S, SP, ST>
where
    I: Input,
    ST: Stats,
    SP: ShMemProvider + 'static,
    S: DeserializeOwned + IfInteresting<I>,
{
    /// The ShmemProvider to use
    shmem_provider: SP,
    /// The stats instance to use
    stats: ST,
    /// A closure or function which generates stats instances for newly spawned clients
    client_init_stats: &'a mut dyn FnMut() -> Result<ST, Error>,
    /// The 'main' function to run for each client forked. This probably shouldn't return
    run_client:
        &'a mut dyn FnMut(Option<S>, LlmpRestartingEventManager<I, S, SP, ST>) -> Result<(), Error>,
    /// The broker port to use
    #[builder(default = 1337_u16)]
    broker_port: u16,
    /// The list of cores to run on
    cores: &'a [usize],
    /// A file name to write all client output to
    #[builder(default = None)]
    stdout_file: Option<&'a str>,
    /// The `ip:port` address of another broker to connect our new broker to for multi-machine
    /// clusters.
    #[builder(default = None)]
    remote_broker_addr: Option<SocketAddr>,
}

#[cfg(feature = "std")]
impl<'a, I, S, SP, ST> Launcher<'a, I, S, SP, ST>
where
    I: Input,
    ST: Stats + Clone,
    SP: ShMemProvider + 'static,
    S: DeserializeOwned + IfInteresting<I>,
{
    /// Launch the broker and the clients and fuzz
    #[cfg(all(unix, feature = "std"))]
    #[allow(clippy::similar_names)]
    pub fn launch(&mut self) -> Result<(), Error> {
        let core_ids = core_affinity::get_core_ids().unwrap();
        let num_cores = core_ids.len();
        let mut handles = vec![];

        println!("spawning on cores: {:?}", self.cores);
        let file = self
            .stdout_file
            .map(|filename| File::create(filename).unwrap());

        //spawn clients
        for (id, bind_to) in core_ids.iter().enumerate().take(num_cores) {
            if self.cores.iter().any(|&x| x == id) {
                self.shmem_provider.pre_fork()?;
                match unsafe { fork() }? {
                    ForkResult::Parent(child) => {
                        self.shmem_provider.post_fork(false)?;
                        handles.push(child.pid);
                        #[cfg(feature = "std")]
                        println!("child spawned and bound to core {}", id);
                    }
                    ForkResult::Child => {
                        self.shmem_provider.post_fork(true)?;

                        #[cfg(feature = "std")]
                        std::thread::sleep(std::time::Duration::from_secs((id + 1) as u64));

                        #[cfg(feature = "std")]
                        if file.is_some() {
                            dup2(file.as_ref().unwrap().as_raw_fd(), libc::STDOUT_FILENO)?;
                            dup2(file.as_ref().unwrap().as_raw_fd(), libc::STDERR_FILENO)?;
                        }
                        //fuzzer client. keeps retrying the connection to broker till the broker starts
                        let stats = (self.client_init_stats)()?;
                        let (state, mgr) = RestartingMgr::builder()
                            .shmem_provider(self.shmem_provider.clone())
                            .stats(stats)
                            .broker_port(self.broker_port)
                            .kind(ManagerKind::Client {
                                cpu_core: Some(*bind_to),
                            })
                            .build()
                            .launch()?;

                        (self.run_client)(state, mgr)?;
                        break;
                    }
                };
            }
        }
        #[cfg(feature = "std")]
        println!("I am broker!!.");

        RestartingMgr::<I, S, SP, ST>::builder()
            .shmem_provider(self.shmem_provider.clone())
            .stats(self.stats.clone())
            .broker_port(self.broker_port)
            .kind(ManagerKind::Broker)
            .remote_broker_addr(self.remote_broker_addr)
            .build()
            .launch()?;

        //broker exited. kill all clients.
        for handle in &handles {
            unsafe {
                libc::kill(*handle, libc::SIGINT);
            }
        }

        Ok(())
    }

    /// Launch the broker and the clients and fuzz
    #[cfg(all(windows, feature = "std"))]
    #[allow(unused_mut)]
    pub fn launch(&mut self) -> Result<(), Error> {
        let is_client = std::env::var(_AFL_LAUNCHER_CLIENT);

        let mut handles = match is_client {
            Ok(core_conf) => {
                //todo: silence stdout and stderr for clients

                // the actual client. do the fuzzing
                let stats = (self.client_init_stats)()?;
                let (state, mgr) = RestartingMgr::<I, S, SP, ST>::builder()
                    .shmem_provider(self.shmem_provider.clone())
                    .stats(stats)
                    .broker_port(self.broker_port)
                    .kind(ManagerKind::Client {
                        cpu_core: Some(CoreId {
                            id: core_conf.parse()?,
                        }),
                    })
                    .build()
                    .unwrap()
                    .launch()?;

                (self.run_client)(state, mgr)?;

                unreachable!("Fuzzer client code should never get here!");
            }
            Err(std::env::VarError::NotPresent) => {
                // I am a broker
                // before going to the broker loop, spawn n clients

                if self.stdout_file.is_some() {
                    println!("Child process file stdio is not supported on Windows yet. Dumping to stdout instead...");
                }

                let core_ids = core_affinity::get_core_ids().unwrap();
                let num_cores = core_ids.len();
                let mut handles = vec![];

                println!("spawning on cores: {:?}", self.cores);

                //spawn clients
                for (id, _) in core_ids.iter().enumerate().take(num_cores) {
                    if self.cores.iter().any(|&x| x == id) {
                        for id in 0..num_cores {
                            let stdio = if self.stdout_file.is_some() {
                                Stdio::inherit()
                            } else {
                                Stdio::null()
                            };

                            if self.cores.iter().any(|&x| x == id) {
                                std::env::set_var(_AFL_LAUNCHER_CLIENT, id.to_string());
                                let child = startable_self()?.stdout(stdio).spawn()?;
                                handles.push(child);
                            }
                        }
                    }
                }

                handles
            }
            Err(_) => panic!("Env variables are broken, received non-unicode!"),
        };

        #[cfg(feature = "std")]
        println!("I am broker!!.");

        RestartingMgr::<I, S, SP, ST>::builder()
            .shmem_provider(self.shmem_provider.clone())
            .stats(self.stats.clone())
            .broker_port(self.broker_port)
            .kind(ManagerKind::Broker)
            .remote_broker_addr(self.remote_broker_addr)
            .build()
            .unwrap()
            .launch()?;

        //broker exited. kill all clients.
        for handle in &mut handles {
            handle.kill()?;
        }

        Ok(())
    }
}

const _AFL_LAUNCHER_CLIENT: &str = &"AFL_LAUNCHER_CLIENT";

/// "Safe" wrapper around dup2
#[cfg(all(unix, feature = "std"))]
fn dup2(fd: i32, device: i32) -> Result<(), Error> {
    match unsafe { libc::dup2(fd, device) } {
        -1 => Err(Error::File(std::io::Error::last_os_error())),
        _ => Ok(()),
    }
}

/// Parses core binding args from user input
/// Returns a Vec of CPU IDs.
/// `./fuzzer --cores 1,2-4,6` -> clients run in cores 1,2,3,4,6
/// ` ./fuzzer --cores all` -> one client runs on each available core
#[must_use]
pub fn parse_core_bind_arg(args: &str) -> Option<Vec<usize>> {
    let mut cores: Vec<usize> = vec![];
    if args == "all" {
        let num_cores = core_affinity::get_core_ids().unwrap().len();
        for x in 0..num_cores {
            cores.push(x);
        }
    } else {
        let core_args: Vec<&str> = args.split(',').collect();

        // ./fuzzer --cores 1,2-4,6 -> clients run in cores 1,2,3,4,6
        // ./fuzzer --cores all -> one client runs in each available core
        for csv in core_args {
            let core_range: Vec<&str> = csv.split('-').collect();
            if core_range.len() == 1 {
                cores.push(core_range[0].parse::<usize>().unwrap());
            } else if core_range.len() == 2 {
                for x in core_range[0].parse::<usize>().unwrap()
                    ..=(core_range[1].parse::<usize>().unwrap())
                {
                    cores.push(x);
                }
            }
        }
    }

    Some(cores)
}
