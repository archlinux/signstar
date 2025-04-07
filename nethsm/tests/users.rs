//! Tests for user creation and manipulation.

use nethsm::NamespaceId;
use nethsm::Passphrase;
use nethsm::UserId;
use nethsm::{NetHsm, UserRole};
use nethsm_tests::ADMIN_USER_ID;
use nethsm_tests::DEFAULT_OPERATOR_USER_PASSPHRASE;
use nethsm_tests::DEFAULT_OPERATOR_USER_REAL_NAME;
use nethsm_tests::NAMESPACE1;
use nethsm_tests::NAMESPACE1_ADMIN_REAL_NAME;
use nethsm_tests::NAMESPACE1_ADMIN_USER_ID;
use nethsm_tests::NAMESPACE1_ADMIN_USER_PASSPHRASE;
use nethsm_tests::NAMESPACE1_OPERATOR_REAL_NAME;
use nethsm_tests::NAMESPACE1_OPERATOR_USER_ID;
use nethsm_tests::NAMESPACE1_OPERATOR_USER_PASSPHRASE;
use nethsm_tests::NAMESPACE2;
use nethsm_tests::NAMESPACE2_ADMIN_REAL_NAME;
use nethsm_tests::NAMESPACE2_ADMIN_USER_ID;
use nethsm_tests::NAMESPACE2_ADMIN_USER_PASSPHRASE;
use nethsm_tests::NAMESPACE2_OPERATOR_REAL_NAME;
use nethsm_tests::NAMESPACE2_OPERATOR_USER_ID;
use nethsm_tests::NAMESPACE2_OPERATOR_USER_PASSPHRASE;
use nethsm_tests::NetHsmImage;
use nethsm_tests::OTHER_OPERATOR_USER_ID;
use nethsm_tests::OTHER_OPERATOR_USER_PASSPHRASE;
use nethsm_tests::OTHER_OPERATOR_USER_REAL_NAME;
use nethsm_tests::provisioned_nethsm;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

/// Second administrator's User ID.
static ADMIN2_USER_ID: &str = "admin1";
/// Second administrator's passphrase.
static ADMIN2_USER_PASSPHRASE: &str = "just-an-admin1-passphrase";
/// Second namespace's metrics user's identifier.
static NAMESPACE2_METRICS_USER_ID: &str = "namespace2~metrics";
/// Second namespace's metrics user's passphrase.
static NAMESPACE2_METRICS_USER_PASSPHRASE: &str = "just-a-namespace2-metrics-passphrase";
/// Second namespace's metrics user's real name.
static NAMESPACE2_METRICS_REAL_NAME: &str = "Namespace2 Metrics";
/// Second namespace's backup user's identifier.
static NAMESPACE2_BACKUP_USER_ID: &str = "namespace2~backup";
/// Second namespace's backup user's passphrase.
static NAMESPACE2_BACKUP_USER_PASSPHRASE: &str = "just-a-namespace2-backup-passphrase";
/// Second namespace's backup user's real name.
static NAMESPACE2_BACKUP_REAL_NAME: &str = "Namespace2 backup";

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn create_users(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = provisioned_nethsm.await?;
    assert_eq!(nethsm.get_users()?.len(), 1);

    // User IDs only consisting of a single char are valid
    nethsm.add_user(
        "test".to_string(),
        UserRole::Operator,
        Passphrase::new("test-passphrase".to_string()),
        Some("a".parse()?),
    )?;
    nethsm.delete_user(&"a".parse()?)?;
    // User IDs only consisting of numbers are valid
    nethsm.add_user(
        "test".to_string(),
        UserRole::Operator,
        Passphrase::new("test-passphrase".to_string()),
        Some("123".parse()?),
    )?;
    nethsm.delete_user(&"123".parse()?)?;
    // User IDs where the Namespace ID is only one char long are valid
    nethsm.add_user(
        "test".to_string(),
        UserRole::Operator,
        Passphrase::new("test-passphrase".to_string()),
        Some("1~user".parse()?),
    )?;
    nethsm.delete_user(&"1~user".parse()?)?;

    nethsm.add_user(
        DEFAULT_OPERATOR_USER_REAL_NAME.to_string(),
        UserRole::Administrator,
        Passphrase::new(ADMIN2_USER_PASSPHRASE.to_string()),
        Some(ADMIN2_USER_ID.parse()?),
    )?;
    println!("Created Administrator User: {}", ADMIN2_USER_ID);
    assert_eq!(nethsm.get_users()?.len(), 2);
    println!(
        "Administrator user data: {:?}",
        nethsm.get_user(&ADMIN2_USER_ID.parse()?)?
    );

    let operator_user = nethsm.add_user(
        DEFAULT_OPERATOR_USER_REAL_NAME.to_string(),
        UserRole::Operator,
        Passphrase::new(DEFAULT_OPERATOR_USER_PASSPHRASE.to_string()),
        None,
    )?;
    println!("Created Operator User: {}", operator_user);
    assert_eq!(nethsm.get_users()?.len(), 3);
    println!("Operator user data: {:?}", nethsm.get_user(&operator_user)?);

    // change passphrase
    nethsm.set_user_passphrase(
        operator_user.clone(),
        Passphrase::new("some-other-operator-passphrase".to_string()),
    )?;

    let other_operator_user = nethsm.add_user(
        OTHER_OPERATOR_USER_REAL_NAME.to_string(),
        UserRole::Operator,
        Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string()),
        Some(OTHER_OPERATOR_USER_ID.parse()?),
    )?;
    println!("Created Operator User: {}", other_operator_user);
    assert_eq!(nethsm.get_users()?.len(), 4);
    println!(
        "Operator user data: {:?}",
        nethsm.get_user(&other_operator_user)?
    );

    nethsm.delete_user(&operator_user)?;
    nethsm.delete_user(&other_operator_user)?;
    assert_eq!(nethsm.get_users()?.len(), 2);

    // a user can not delete itself
    assert!(nethsm.delete_user(&ADMIN_USER_ID.parse()?).is_err());

    // another Administrator can delete the initial Administrator
    nethsm.use_credentials(&ADMIN2_USER_ID.parse()?)?;
    nethsm.delete_user(&ADMIN_USER_ID.parse()?)?;
    assert_eq!(nethsm.get_users()?.len(), 1);

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn create_users_in_namespaces(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = provisioned_nethsm.await?;
    let namespace1: NamespaceId = NAMESPACE1.parse()?;
    let namespace1_admin_user_id: UserId = NAMESPACE1_ADMIN_USER_ID.parse()?;
    let namespace1_operator_user_id: UserId = NAMESPACE1_OPERATOR_USER_ID.parse()?;
    let namespace2: NamespaceId = NAMESPACE2.parse()?;
    let namespace2_admin_user_id: UserId = NAMESPACE2_ADMIN_USER_ID.parse()?;
    let namespace2_operator_user_id: UserId = NAMESPACE2_OPERATOR_USER_ID.parse()?;
    let namespace2_metrics_user_id: UserId = NAMESPACE2_METRICS_USER_ID.parse()?;
    let namespace2_backup_user_id: UserId = NAMESPACE2_BACKUP_USER_ID.parse()?;

    // add namespace1
    assert_eq!(nethsm.get_users()?.len(), 1);
    // R-Administrators can add Administrator users for namespaces that do not yet exist
    assert!(
        nethsm
            .add_user(
                NAMESPACE1_ADMIN_REAL_NAME.to_string(),
                UserRole::Administrator,
                Passphrase::new(NAMESPACE1_ADMIN_USER_PASSPHRASE.to_string()),
                Some(namespace1_admin_user_id.clone()),
            )
            .is_ok()
    );
    println!(
        "Created {} admin user: {}",
        &namespace1, &namespace1_admin_user_id
    );
    assert_eq!(nethsm.get_users()?.len(), 2);
    println!(
        "Namespace1 admin user data: {:?}",
        nethsm.get_user(&namespace1_admin_user_id)?
    );
    // R-Administrators can add Operator users for namespaces that do not yet exist
    assert!(
        nethsm
            .add_user(
                NAMESPACE1_OPERATOR_REAL_NAME.to_string(),
                UserRole::Operator,
                Passphrase::new(NAMESPACE1_OPERATOR_USER_PASSPHRASE.to_string()),
                Some(namespace1_operator_user_id.clone()),
            )
            .is_ok()
    );
    println!(
        "Created {} Operator user: {}",
        &namespace1, &namespace1_operator_user_id
    );
    assert_eq!(nethsm.get_users()?.len(), 3);
    println!(
        "Namespace Operator user data: {:?}",
        nethsm.get_user(&namespace1_operator_user_id)?
    );

    nethsm.add_namespace(&namespace1)?;
    println!("Namespaces {:?}", nethsm.get_namespaces()?);
    assert_eq!(nethsm.get_namespaces()?.len(), 1);

    // add namespace2
    nethsm.add_user(
        NAMESPACE2_ADMIN_REAL_NAME.to_string(),
        UserRole::Administrator,
        Passphrase::new(NAMESPACE2_ADMIN_USER_PASSPHRASE.to_string()),
        Some(namespace2_admin_user_id.clone()),
    )?;
    println!(
        "Created {} Administrator user: {}",
        &namespace2, NAMESPACE2_ADMIN_USER_ID
    );
    assert_eq!(nethsm.get_users()?.len(), 4);
    println!(
        "Namespace2 Administrator user data: {:?}",
        nethsm.get_user(&namespace2_admin_user_id)?
    );
    // R-Administrators can not add users in the Backup role to a not yet existing namespace
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_BACKUP_REAL_NAME.to_string(),
                UserRole::Backup,
                Passphrase::new(NAMESPACE2_BACKUP_USER_PASSPHRASE.to_string()),
                Some(namespace2_backup_user_id.clone()),
            )
            .is_err()
    );
    // R-Administrators can not add users in the Metrics role to a not yet existing namespace
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_METRICS_REAL_NAME.to_string(),
                UserRole::Metrics,
                Passphrase::new(NAMESPACE2_METRICS_USER_PASSPHRASE.to_string()),
                Some(namespace2_metrics_user_id.clone()),
            )
            .is_err()
    );
    nethsm.add_namespace(&namespace2)?;
    println!("Namespaces {:?}", nethsm.get_namespaces()?);
    assert_eq!(nethsm.get_namespaces()?.len(), 2);

    // R-Administrators can not change the passphrase for a namespace user
    assert!(
        nethsm
            .set_user_passphrase(
                namespace1_admin_user_id.clone(),
                Passphrase::new("some-other-passphrase".to_string()),
            )
            .is_err()
    );
    // R-Administrators can not add a user to a namespace (but their own)
    assert!(
        nethsm
            .add_user(
                NAMESPACE1_OPERATOR_REAL_NAME.to_string(),
                UserRole::Operator,
                Passphrase::new(NAMESPACE1_OPERATOR_USER_PASSPHRASE.to_string()),
                Some(namespace1_operator_user_id.clone()),
            )
            .is_err()
    );

    // namespace1
    nethsm.use_credentials(&namespace1_admin_user_id)?;
    // N-Administrators only see users in their own namespace
    assert_eq!(nethsm.get_users()?.len(), 2);
    // N-Administrators can not see namespaces
    assert!(nethsm.get_namespaces().is_err());
    // N-Administrators can not delete namespaces
    assert!(nethsm.delete_namespace(&namespace1).is_err());
    // N-Administrators can not add namespaces
    assert!(nethsm.add_namespace(&namespace2).is_err());
    // N-Administrators can not get namespaces
    assert!(nethsm.get_namespaces().is_err());
    // N-Administrators can not add users in other namespaces
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_OPERATOR_REAL_NAME.to_string(),
                UserRole::Operator,
                Passphrase::new(NAMESPACE2_OPERATOR_USER_PASSPHRASE.to_string()),
                Some(namespace2_operator_user_id.clone()),
            )
            .is_err()
    );
    // N-Administrators can delete users in their own namespace
    assert!(nethsm.delete_user(&namespace1_operator_user_id).is_ok());
    assert_eq!(nethsm.get_users()?.len(), 1);

    // namespace2
    nethsm.use_credentials(&namespace2_admin_user_id)?;
    // N-Administrators can add users in the Operator role in their own namespace
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_OPERATOR_REAL_NAME.to_string(),
                UserRole::Operator,
                Passphrase::new(NAMESPACE2_OPERATOR_USER_PASSPHRASE.to_string()),
                Some(namespace2_operator_user_id.clone()),
            )
            .is_ok()
    );
    // N-Administrators can not add users in the Backup role to their own namespace
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_BACKUP_REAL_NAME.to_string(),
                UserRole::Backup,
                Passphrase::new(NAMESPACE2_BACKUP_USER_PASSPHRASE.to_string()),
                Some(namespace2_backup_user_id.clone()),
            )
            .is_err()
    );
    // N-Administrators can not add users in the Metrics role to their own namespace
    assert!(
        nethsm
            .add_user(
                NAMESPACE2_METRICS_REAL_NAME.to_string(),
                UserRole::Metrics,
                Passphrase::new(NAMESPACE2_METRICS_USER_PASSPHRASE.to_string()),
                Some(namespace2_metrics_user_id.clone()),
            )
            .is_err()
    );
    println!("{:?}", nethsm.get_users()?);
    // N-Administrators can add users without specifying a User ID and the newly created user will
    // inherit their namespace
    let custom_user = nethsm.add_user(
        "Some Custom".to_string(),
        UserRole::Operator,
        Passphrase::new("some-custom-user-passphrase".to_string()),
        None,
    )?;
    println!("Created custom user {}", custom_user);

    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    assert_eq!(nethsm.get_namespaces()?.len(), 2);
    assert_eq!(nethsm.get_users()?.len(), 5);
    // R-Administrators can not delete users in a namespace
    assert!(nethsm.delete_user(&namespace1_admin_user_id).is_err());
    assert!(nethsm.delete_user(&namespace1_operator_user_id).is_err());
    // R-Administrators can delete namespaces
    nethsm.delete_namespace(&namespace1)?;
    assert_eq!(nethsm.get_namespaces()?.len(), 1);
    nethsm.delete_namespace(&namespace2)?;
    assert!(nethsm.get_namespaces()?.is_empty());
    // R-Administrators can delete users in a namespace if the namespace has been deleted
    assert!(nethsm.delete_user(&namespace1_admin_user_id).is_ok());
    assert!(nethsm.delete_user(&namespace2_admin_user_id).is_ok());
    assert!(nethsm.delete_user(&namespace2_operator_user_id).is_ok());
    assert!(nethsm.delete_user(&custom_user).is_ok());
    println!("{:?}", nethsm.get_users()?);
    assert_eq!(nethsm.get_users()?.len(), 1);

    Ok(())
}
