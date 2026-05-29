//! Types for describing objects stored on a YubiHSM2.

mod capability;
mod error;
mod id;
mod key;

pub use capability::{Capabilities, Capability};
pub use error::Error;
pub use id::{Id, ObjectId};
pub use key::{Domain, Domains, KeyInfo};
