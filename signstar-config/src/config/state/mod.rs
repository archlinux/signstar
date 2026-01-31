//! State representation of Signstar configuration files.

mod common;
#[cfg(feature = "nethsm")]
mod nethsm;

pub use common::KeyCertificateState;
#[cfg(feature = "nethsm")]
pub use nethsm::{
    KeyState,
    KeyStateComparisonFailure,
    KeyStates,
    SignstarConfigNetHsmState,
    UserState,
    UserStateComparisonFailure,
    UserStates,
};
