//! State handling

/// The state of administrative secrets on a Signstar host.
pub enum AdminCredsState {
    /// Administrative secrets are present
    Present,
    /// Administrative secrets are missing
    Missing,
}
