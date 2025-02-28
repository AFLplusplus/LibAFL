//! # allocator
//! The allocator is split into two parts:
//! - `backend` - The is the portion responsible for allocating the underlying
//!   memory used by the application.
//! - `frontend` - The portion is responsible for applying the value-added asan
//!   features on behalf of incoming user requests for allocations including
//!   red-zones, poisoning and memory tracking.
pub mod backend;
pub mod frontend;
