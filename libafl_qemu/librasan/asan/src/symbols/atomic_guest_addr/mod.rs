#[cfg(feature = "single-threaded")]
pub mod single_threaded;

#[cfg(not(feature = "single-threaded"))]
pub mod multi_threaded;
