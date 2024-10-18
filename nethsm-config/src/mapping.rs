use nethsm::UserId;
use serde::{Deserialize, Serialize};

use crate::SystemWideUserId;

/// Errors related to mapping
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`UserId`] is used both for a user in the [`Metrics`][`nethsm::UserRole::Metrics`] and
    /// [`Operator`][`nethsm::UserRole::Operator`] role
    #[error("The NetHsm user {metrics_user} is both in the Metrics and Operator role!")]
    MetricsAlsoOperator { metrics_user: SystemWideUserId },
}

/// A set of users with unique [`UserId`]s, used for metrics retrieval
///
/// This struct tracks a user that is intended for the use in the
/// [`Metrics`][`nethsm::UserRole::Metrics`] role and a list of users, that are intended to be used
/// in the [`Operator`][`nethsm::UserRole::Operator`] role.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
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
    /// use nethsm_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// // this fails because there are duplicate UserIds
    /// assert!(NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["metrics1".parse()?, "user2".parse()?,],
    /// )
    /// .is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(metrics_user: SystemWideUserId, operator_users: Vec<UserId>) -> Result<Self, Error> {
        // prevent duplicate metrics and operator users
        if operator_users.contains(&metrics_user.clone().into()) {
            return Err(Error::MetricsAlsoOperator { metrics_user });
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
    /// use nethsm_config::NetHsmMetricsUsers;
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
}
