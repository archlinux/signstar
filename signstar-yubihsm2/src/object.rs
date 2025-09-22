//! Types for describing objects stored on a YubiHSM2.

mod capability;
mod id;
mod key;

pub use capability::{Capabilities, Capability};
pub use id::ObjectId;
pub use key::{Domain, KeyInfo};
