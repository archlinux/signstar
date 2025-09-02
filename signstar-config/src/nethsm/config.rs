//! [`NetHsm`] specific integration for the [`crate::config`] module.

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{NamespaceId, UserId, UserRole};
use serde::{Deserialize, Serialize};

use crate::{Error, SystemWideUserId};

/// A filter for retrieving information about users and keys.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FilterUserKeys {
    /// Consider both system-wide and namespaced users and keys.
    All,

    /// Only consider users and keys that are in a namespace.
    Namespaced,

    /// Only consider users and keys that match a specific [`NamespaceId`].
    Namespace(NamespaceId),

    /// Only consider system-wide users and keys.
    SystemWide,

    /// Only consider users and keys that match a specific tag.
    Tag(String),
}

/// A set of users with unique [`UserId`]s, used for metrics retrieval
///
/// This struct tracks a user that is intended for the use in the
/// [`Metrics`][`nethsm::UserRole::Metrics`] role and a list of users, that are intended to be used
/// in the [`Operator`][`nethsm::UserRole::Operator`] role.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NetHsmMetricsUsers {
    metrics_user: SystemWideUserId,
    operator_users: Vec<UserId>,
}

impl NetHsmMetricsUsers {
    /// Creates a new [`NetHsmMetricsUsers`]
    ///
    /// # Error
    ///
    /// Returns an error, if the provided [`UserId`] of the `metrics_user` is duplicated in the
    /// provided `operator_users`.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// // this fails because there are duplicate UserIds
    /// assert!(
    ///     NetHsmMetricsUsers::new(
    ///         "metrics1".parse()?,
    ///         vec!["metrics1".parse()?, "user2".parse()?,],
    ///     )
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(metrics_user: SystemWideUserId, operator_users: Vec<UserId>) -> Result<Self, Error> {
        // prevent duplicate metrics and operator users
        if operator_users.contains(&metrics_user.clone().into()) {
            return Err(crate::ConfigError::MetricsAlsoOperator { metrics_user }.into());
        }

        Ok(Self {
            metrics_user,
            operator_users,
        })
    }

    /// Returns all tracked [`UserId`]s of the [`NetHsmMetricsUsers`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    /// use signstar_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm_metrics_users = NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// assert_eq!(
    ///     nethsm_metrics_users.get_users(),
    ///     vec![
    ///         UserId::new("metrics1".to_string())?,
    ///         UserId::new("user1".to_string())?,
    ///         UserId::new("user2".to_string())?
    ///     ]
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_users(&self) -> Vec<UserId> {
        [
            vec![self.metrics_user.clone().into()],
            self.operator_users.clone(),
        ]
        .concat()
    }

    /// Returns all tracked [`UserId`]s and their respective [`UserRole`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{UserId, UserRole};
    /// use signstar_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm_metrics_users = NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// assert_eq!(
    ///     nethsm_metrics_users.get_users_and_roles(),
    ///     vec![
    ///         (UserId::new("metrics1".to_string())?, UserRole::Metrics),
    ///         (UserId::new("user1".to_string())?, UserRole::Operator),
    ///         (UserId::new("user2".to_string())?, UserRole::Operator)
    ///     ]
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_users_and_roles(&self) -> Vec<(UserId, UserRole)> {
        [
            vec![(self.metrics_user.clone().into(), UserRole::Metrics)],
            self.operator_users
                .iter()
                .map(|user| (user.clone(), UserRole::Operator))
                .collect(),
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    #[test]
    fn nethsm_metrics_users_succeeds() -> TestResult {
        NetHsmMetricsUsers::new(
            SystemWideUserId::new("metrics".to_string())?,
            vec![
                UserId::new("operator".to_string())?,
                UserId::new("ns1~operator".to_string())?,
            ],
        )?;
        Ok(())
    }

    #[test]
    fn nethsm_metrics_users_fails() -> TestResult {
        if let Ok(user) = NetHsmMetricsUsers::new(
            SystemWideUserId::new("metrics".to_string())?,
            vec![
                UserId::new("metrics".to_string())?,
                UserId::new("ns1~operator".to_string())?,
            ],
        ) {
            panic!("Succeeded creating a NetHsmMetricsUsers, but should have failed:\n{user:?}")
        }
        Ok(())
    }
}
