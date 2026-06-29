use signstar_yubihsm2::object::Id;

/// An error that may occur when using YubiHSM2 config objects.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A generic error.
    #[error("A generic YubiHSM2 backend error occurred while {context}")]
    Generic {
        /// The context in which the error happened.
        ///
        /// This is meant to complete the sentence "A generic YubiHSM2 backend error occurred while
        /// ".
        context: &'static str,
    },

    /// An error occurred while retrieving data from the backend.
    #[error("YubiHSM2 data retrieval error while {context}: {source}")]
    DataRetrieval {
        /// The reason why data retrieval failed.
        ///
        /// This is meant to complete the sentence "YubiHSM2 data retrieval error while ".
        context: &'static str,

        /// The error source.
        source: signstar_yubihsm2::Error,
    },

    /// Encountered duplicate credentials.
    #[error(
        "Duplicate credentials {} encountered while {context}",
        duplicates.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
    )]
    DuplicateCredentials {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Duplicate credentials {} encountered while ".
        context: &'static str,

        /// The IDs of duplicate credentials.
        duplicates: Vec<Id>,
    },

    /// Encountered user mappings without credentials.
    #[error(
        "User mapping(s) without credentials encountered while {context}: {}",
        ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
    )]
    UserMappingWithoutCredentials {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "User mapping without credentials ({})
        /// encountered while ".
        context: &'static str,

        /// The IDs of the user mappings without credentials.
        ids: Vec<Id>,
    },

    /// Credentials without a matching user mapping found.
    #[error(
        "Credentials without a matching user mapping encountered while {context}: {}",
        ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", "),
    )]
    CredentialsWithoutUserMapping {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "User mapping without credentials ({})
        /// encountered while ".
        context: &'static str,

        /// The IDs of the user mappings without credentials.
        ids: Vec<Id>,
    },

    /// An error occurred in the logic of a scenario.
    #[error("YubiHSM2 scenario logic error because {context}")]
    ScenarioLogic {
        /// The reason why the scenario logic failed.
        ///
        /// This is meant to complete the sentence "YubiHSM2 scenario logic error because ".
        context: &'static str,
    },
}
