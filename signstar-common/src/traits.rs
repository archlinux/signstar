//! Common traits for signstar related crates.

/// An interface for simple checks against a Signstar backend.
///
/// Backends may or may not be connected to a given Signstar host.
/// This interface helps to establish whether they should be considered when evaluating state, or
/// not.
pub trait BackendCheck {
    /// Checks whether a Signstar backend connection is available on the current host.
    ///
    /// This function is meant as a simple check as to whether a backend is available to the
    /// Signstar host executing this function, or not.
    ///
    /// It is not meant to track specific errors as to why a connection cannot be established.
    /// However, implementations are advised to emit meaningful warning and error messages, if a
    /// specific failure is encountered with a backend.
    ///
    /// # Note
    ///
    /// Implementations should only return `true`, if they are able to establish connection from
    /// the current Signstar host.
    /// Establishing a connection should ideally happen using unauthenticated functionality of the
    /// backend.
    /// Calling this function should answer the question "Is the backend connected to this host?".
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_common::traits::BackendCheck;
    ///
    /// // A dummy backend, that doesn't do anything.
    /// struct DummyBackend;
    ///
    /// impl BackendCheck for DummyBackend {
    ///     /// This backend is always available.
    ///     fn is_available(&self) -> bool {
    ///         true
    ///     }
    ///
    ///     /// This backend is always considered provisioned.
    ///     fn is_provisioned(&self) -> bool {
    ///         true
    ///     }
    /// }
    ///
    /// # fn main() -> testresult::TestResult {
    /// let backend = DummyBackend;
    /// assert!(backend.is_available());
    /// # Ok(())
    /// # }
    /// ```
    fn is_available(&self) -> bool;

    /// Checks whether a Signstar backend has been provisioned.
    ///
    /// This function is meant as a simple check as to whether a backend is still using factory
    /// settings, or not.
    ///
    /// It is not meant to track specific errors as to why a connection cannot be established, etc.
    /// However, implementations are advised to emit meaningful warning and error messages, if a
    /// specific failure is encountered with a backend.
    ///
    /// # Note
    ///
    /// Implementations should only return `true`, if they can ensure, that the backend has been
    /// altered from its factory settings (indicators for this may differe depending on backend).
    /// Calling this function should answer the question "Is the backend connected to this host and
    /// is it provisioned?".
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_common::traits::BackendCheck;
    ///
    /// // A dummy backend, that doesn't do anything.
    /// struct DummyBackend;
    ///
    /// impl BackendCheck for DummyBackend {
    ///     /// This backend is always available.
    ///     fn is_available(&self) -> bool {
    ///         true
    ///     }
    ///
    ///     /// This backend is always considered provisioned.
    ///     fn is_provisioned(&self) -> bool {
    ///         true
    ///     }
    /// }
    ///
    /// # fn main() -> testresult::TestResult {
    /// let backend = DummyBackend;
    /// assert!(backend.is_provisioned());
    /// # Ok(())
    /// # }
    /// ```
    fn is_provisioned(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyBackend;

    impl BackendCheck for DummyBackend {
        fn is_available(&self) -> bool {
            true
        }

        fn is_provisioned(&self) -> bool {
            true
        }
    }

    /// Ensures, that [`BackendConnectionTest::is_available`] works for a simple implementation.
    #[test]
    fn backend_check_is_available() {
        let backend = DummyBackend;
        assert!(backend.is_available());
    }

    /// Ensures, that [`BackendConnectionTest::uses_default_credentials`] works for a simple
    /// implementation.
    #[test]
    fn backend_check_uses_default_credentials() {
        let backend = DummyBackend;
        assert!(backend.is_provisioned());
    }
}
