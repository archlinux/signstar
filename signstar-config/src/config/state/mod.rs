//! State representation of Signstar configuration files.

mod common;
mod nethsm;

pub use common::KeyCertificateState;
pub use nethsm::{
    KeyState,
    KeyStateComparisonFailure,
    KeyStates,
    SignstarConfigNetHsmState,
    UserState,
    UserStateComparisonFailure,
    UserStates,
};
