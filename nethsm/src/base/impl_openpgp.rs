//! [`NetHsm`] implementation for OpenPGP functionality.

use log::debug;

#[cfg(doc)]
use crate::{Credentials, SystemState, UserRole};
use crate::{
    DateTime,
    Error,
    KeyId,
    NetHsm,
    OpenPgpKeyUsageFlags,
    OpenPgpUserId,
    OpenPgpVersion,
    Utc,
    base::utils::user_or_no_user_string,
};

impl NetHsm {
    /// Creates an [OpenPGP certificate] for an existing key.
    ///
    /// The NetHSM key identified by `key_id` is used to issue required [binding signatures] (e.g.
    /// those for the [User ID] defined by `user_id`).
    /// Using `flags` it is possible to define the key's [capabilities] and with `created_at` to
    /// provide the certificate's creation time.
    /// Using `version` the OpenPGP version is provided (currently only [`OpenPgpVersion::V4`] is
    /// supported).
    /// The resulting [OpenPGP certificate] is returned as vector of bytes.
    ///
    /// To make use of the [OpenPGP certificate] (e.g. with
    /// [`openpgp_sign`][`NetHsm::openpgp_sign`]), it should be added as certificate for the key
    /// using [`import_key_certificate`][`NetHsm::import_key_certificate`].
    ///
    /// This call requires using a user in the [`Operator`][`UserRole::Operator`] [role], which
    /// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
    /// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating an [OpenPGP certificate] for a key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Panics
    ///
    /// Panics if the currently unimplemented [`OpenPgpVersion::V6`] is provided as `version`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     OpenPgpVersion,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".parse()?),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // create an OpenPGP certificate for the key with ID "signing1"
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// assert!(
    ///     !nethsm
    ///         .create_openpgp_cert(
    ///             &"signing1".parse()?,
    ///             OpenPgpKeyUsageFlags::default(),
    ///             "Test <test@example.org>".parse()?,
    ///             SystemTime::now().into(),
    ///             OpenPgpVersion::V4,
    ///         )?
    ///         .is_empty()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [OpenPGP certificate]: https://openpgp.dev/book/certificates.html
    /// [binding signatures]: https://openpgp.dev/book/signing_components.html#binding-signatures
    /// [User ID]: https://openpgp.dev/book/glossary.html#term-User-ID
    /// [key certificate]: https://docs.nitrokey.com/nethsm/operation#key-certificates
    /// [capabilities]: https://openpgp.dev/book/glossary.html#term-Capability
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn create_openpgp_cert(
        &self,
        key_id: &KeyId,
        flags: OpenPgpKeyUsageFlags,
        user_id: OpenPgpUserId,
        created_at: DateTime<Utc>,
        version: OpenPgpVersion,
    ) -> Result<Vec<u8>, Error> {
        debug!(
            "Create an OpenPGP certificate (User ID: {user_id}; flags: {:?}; creation date: {created_at}; version: {version}) for key \"{key_id}\" on the NetHSM at {} using {}",
            flags.as_ref(),
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        Ok(crate::openpgp::add_certificate(
            self, flags, key_id, user_id, created_at, version,
        )?)
    }

    /// Creates an [OpenPGP signature] for a message.
    ///
    /// Signs the `message` using the key identified by `key_id` and returns a binary [OpenPGP data
    /// signature].
    ///
    /// This call requires using a user in the [`Operator`][`UserRole::Operator`] [role], which
    /// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
    /// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating an [OpenPGP signature] for the `message` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     OpenPgpVersion,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".parse()?),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // create an OpenPGP certificate for the key with ID "signing1"
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     &"signing1".parse()?,
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>".parse()?,
    ///     SystemTime::now().into(),
    ///     OpenPgpVersion::V4,
    /// )?;
    /// // import the OpenPGP certificate as key certificate
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.import_key_certificate(&"signing1".parse()?, openpgp_cert)?;
    ///
    /// // create OpenPGP signature
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// assert!(
    ///     !nethsm
    ///         .openpgp_sign(&"signing1".parse()?, b"sample message")?
    ///         .is_empty()
    /// );
    /// # Ok(()) }
    /// ```
    /// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
    /// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn openpgp_sign(&self, key_id: &KeyId, message: &[u8]) -> Result<Vec<u8>, Error> {
        debug!(
            "Create an OpenPGP signature for a message with key \"{key_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        Ok(crate::openpgp::sign(self, key_id, message)?)
    }

    /// Generates an armored OpenPGP signature based on provided hasher state.
    ///
    /// Signs the hasher `state` using the key identified by `key_id`
    /// and returns a binary [OpenPGP data signature].
    ///
    /// This call requires using a user in the [`Operator`][`UserRole::Operator`] [role], which
    /// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
    /// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating an [OpenPGP signature] for the hasher state fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     OpenPgpVersion,
    ///     Passphrase,
    ///     UserRole,
    /// };
    /// use sha2::{Digest, Sha512};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".parse()?),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // create an OpenPGP certificate for the key with ID "signing1"
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     &"signing1".parse()?,
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>".parse()?,
    ///     SystemTime::now().into(),
    ///     OpenPgpVersion::V4,
    /// )?;
    /// // import the OpenPGP certificate as key certificate
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.import_key_certificate(&"signing1".parse()?, openpgp_cert)?;
    ///
    /// let mut state = Sha512::new();
    /// state.update(b"Hello world!");
    ///
    /// // create OpenPGP signature
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// assert!(
    ///     !nethsm
    ///         .openpgp_sign_state(&"signing1".parse()?, state)?
    ///         .is_empty()
    /// );
    /// # Ok(()) }
    /// ```
    /// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
    /// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn openpgp_sign_state(
        &self,
        key_id: &KeyId,
        state: sha2::Sha512,
    ) -> Result<String, crate::Error> {
        debug!(
            "Create an OpenPGP signature for a hasher state with key \"{key_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        Ok(crate::openpgp::sign_hasher_state(self, key_id, state)?)
    }
}
