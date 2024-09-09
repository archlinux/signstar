mod common;
use common::nethsm_with_users;
use common::NetHsmImage;
use common::ADMIN_USER_ID;
use common::DEFAULT_AES_BITS;
use common::DEFAULT_OPERATOR_USER_ID;
use common::DEFAULT_RSA_BITS;
use common::NAMESPACE1;
use common::NAMESPACE1_ADMIN_USER_ID;
use common::NAMESPACE1_OPERATOR_USER_ID;
use common::NAMESPACE2_ADMIN_USER_ID;
use common::NAMESPACE2_OPERATOR_USER_ID;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use nethsm::NamespaceId;
use nethsm::PrivateKeyImport;
use nethsm::UserId;
use nethsm::{KeyMechanism, KeyType, NetHsm};
use rstest::{fixture, rstest};
use rustainers::Container;
use testresult::TestResult;

#[rstest]
#[ignore = "requires Podman"]
#[case(KeyType::Curve25519, vec![KeyMechanism::EdDsaSignature], None)]
#[ignore = "requires Podman"]
#[case(KeyType::EcP224, vec![KeyMechanism::EcdsaSignature], None)]
#[ignore = "requires Podman"]
#[case(KeyType::EcP256, vec![KeyMechanism::EcdsaSignature], None)]
#[ignore = "requires Podman"]
#[case(KeyType::EcP384, vec![KeyMechanism::EcdsaSignature], None)]
#[ignore = "requires Podman"]
#[case(KeyType::EcP521, vec![KeyMechanism::EcdsaSignature], None)]
#[ignore = "requires Podman"]
#[case(KeyType::Generic, vec![KeyMechanism::AesDecryptionCbc, KeyMechanism::AesEncryptionCbc], Some(DEFAULT_AES_BITS))]
#[ignore = "requires Podman"]
#[case(KeyType::Rsa, vec![KeyMechanism::RsaSignaturePssSha512], Some(DEFAULT_RSA_BITS))]
#[tokio::test]
async fn generate_keys(
    #[case] key_type: KeyType,
    #[case] mechanisms: Vec<KeyMechanism>,
    #[case] length: Option<u32>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let sw_tag = "sw".to_string();
    let ns1_tag = "ns1".to_string();
    let ns2_tag = "ns2".to_string();
    let admin_user_id: UserId = ADMIN_USER_ID.parse()?;
    let default_operator_user_id: UserId = DEFAULT_OPERATOR_USER_ID.parse()?;
    let namespace1: NamespaceId = NAMESPACE1.parse()?;
    let namespace1_admin_user_id: UserId = NAMESPACE1_ADMIN_USER_ID.parse()?;
    let namespace1_operator_user_id: UserId = NAMESPACE1_OPERATOR_USER_ID.parse()?;
    let namespace2_admin_user_id: UserId = NAMESPACE2_ADMIN_USER_ID.parse()?;
    let namespace2_operator_user_id: UserId = NAMESPACE2_OPERATOR_USER_ID.parse()?;

    let _free_key = nethsm.generate_key(key_type, mechanisms.clone(), length, None, None)?;
    let sw_key = nethsm.generate_key(
        key_type,
        mechanisms.clone(),
        length,
        None,
        Some(vec![sw_tag.clone()]),
    )?;
    println!("Created system-wide key: {}", &sw_key);
    nethsm.add_user_tag(&default_operator_user_id, &sw_tag)?;
    println!(
        "system-wide operator tags: {:?}",
        nethsm.get_user_tags(&default_operator_user_id)?
    );

    // namespace1
    nethsm.use_credentials(&namespace1_admin_user_id)?;
    let ns1_key = nethsm.generate_key(
        key_type,
        mechanisms.clone(),
        length,
        None,
        Some(vec![ns1_tag.clone()]),
    )?;
    println!("Created namespace1 key: {}", &ns1_key);
    // namespace operator can get key info without tags
    nethsm.use_credentials(&namespace1_operator_user_id)?;
    println!(
        "{} key accessed by {} before tagging: {:?}",
        &ns1_key,
        &namespace1_operator_user_id,
        nethsm.get_key(&ns1_key)?
    );
    // "generic" keys are symmetric encryption keys (and thus have no public key)
    if key_type != KeyType::Generic {
        // namespace operator can get public key of key without tags
        let public_key = nethsm.get_public_key(&ns1_key)?;
        println!(
            "{} public key retrieved by {}, before tagging: {:?}",
            &ns1_key, &namespace1_operator_user_id, &public_key
        );
        // namespace administrator can import a certificate for a key
        nethsm.use_credentials(&namespace1_admin_user_id)?;
        nethsm.import_key_certificate(&ns1_key, public_key.clone().into_bytes())?;
        // namespace operator can get the key certificate without tags
        nethsm.use_credentials(&namespace1_operator_user_id)?;
        let key_cert = nethsm.get_key_certificate(&ns1_key)?;
        assert_eq!(key_cert, public_key.into_bytes());
    }

    nethsm.use_credentials(&namespace1_admin_user_id)?;
    nethsm.add_user_tag(&namespace1_operator_user_id, &ns1_tag)?;
    println!(
        "namespace1 operator tags: {:?}",
        nethsm.get_user_tags(&namespace1_operator_user_id)?
    );

    // namespace2
    nethsm.use_credentials(&namespace2_admin_user_id)?;
    let ns2_key = nethsm.generate_key(
        key_type,
        mechanisms.clone(),
        length,
        None,
        Some(vec![ns2_tag.clone()]),
    )?;
    println!("Created namespace2 key: {}", &ns2_key);
    nethsm.add_user_tag(&namespace2_operator_user_id, &ns2_tag)?;
    println!(
        "namespace2 operator tags: {:?}",
        nethsm.get_user_tags(&namespace2_operator_user_id)?
    );

    // system-wide operator only has access to system-wide keys
    nethsm.use_credentials(&default_operator_user_id)?;
    assert!(nethsm.get_keys(None)?.len() == 2);
    println!("system-wide keys: {:?}", nethsm.get_keys(None)?);
    assert!(nethsm.get_key(&sw_key).is_ok());
    println!("system-wide key: {:?}", nethsm.get_key(&sw_key)?);

    // namespace1 operator only has access to namespace1 keys
    nethsm.use_credentials(&namespace1_operator_user_id)?;
    assert!(nethsm.get_keys(None)?.len() == 1);
    println!("namespace1 keys: {:?}", nethsm.get_keys(None)?);
    assert!(nethsm.get_key(&ns1_key).is_ok());
    println!("namespace1 key: {:?}", nethsm.get_key(&ns1_key)?);

    // namespace2 operator only has access to namespace2 keys
    nethsm.use_credentials(&namespace2_operator_user_id)?;
    assert!(nethsm.get_keys(None)?.len() == 1);
    println!("namespace2 keys: {:?}", nethsm.get_keys(None)?);
    assert!(nethsm.get_key(&ns2_key).is_ok());
    println!("namespace2 key: {:?}", nethsm.get_key(&ns2_key)?);

    nethsm.use_credentials(&admin_user_id)?;
    // R-Administrator is unable to add or delete namespace user tags
    assert!(nethsm
        .add_user_tag(&namespace1_operator_user_id, "test")
        .is_err());
    assert!(nethsm
        .delete_user_tag(&namespace1_operator_user_id, &ns1_tag)
        .is_err());
    assert!(nethsm
        .add_user_tag(&namespace2_operator_user_id, "test")
        .is_err());
    assert!(nethsm
        .delete_user_tag(&namespace2_operator_user_id, &ns2_tag)
        .is_err());
    // R-Administrator is able to see namespace user tags
    println!(
        "namespace1 operator tags: {:?}",
        nethsm.get_user_tags(&namespace1_operator_user_id)?
    );
    println!(
        "namespace2 operator tags: {:?}",
        nethsm.get_user_tags(&namespace2_operator_user_id)?
    );

    // when the namespace is deleted, all key access is gone too
    nethsm.delete_namespace(&namespace1)?;
    println!("all users: {:?}", nethsm.get_users()?);
    println!(
        "namespace1 operator: {:?}",
        nethsm.get_user(&namespace1_operator_user_id)?
    );
    println!(
        "namespace1 operator tags: {:?}",
        nethsm.get_user_tags(&namespace1_operator_user_id)?
    );
    nethsm.use_credentials(&namespace1_operator_user_id)?;
    // although the namespace1 operator is now not in a namespace anymore it does not have access to
    // any other key!
    assert!(nethsm.get_keys(None).is_err());
    assert!(nethsm.get_key(&ns1_key).is_err());
    nethsm.use_credentials(&namespace1_admin_user_id)?;
    // although the namespace1 administrator is now not in a namespace anymore it does not have
    // access to any other key!
    assert!(nethsm.get_keys(None).is_err());
    assert!(nethsm.get_key(&ns1_key).is_err());

    Ok(())
}

#[fixture]
fn ed25519_key() -> TestResult<PrivateKeyImport> {
    let private_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

    Ok(PrivateKeyImport::new(
        KeyType::Curve25519,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[fixture]
fn ecp224_key() -> TestResult<PrivateKeyImport> {
    let private_key = p224::SecretKey::random(&mut rand::rngs::OsRng);

    Ok(PrivateKeyImport::new(
        KeyType::EcP224,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[fixture]
fn ecp256_key() -> TestResult<PrivateKeyImport> {
    let private_key = p256::SecretKey::random(&mut rand::rngs::OsRng);

    Ok(PrivateKeyImport::new(
        KeyType::EcP256,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[fixture]
fn ecp384_key() -> TestResult<PrivateKeyImport> {
    let private_key = p384::SecretKey::random(&mut rand::rngs::OsRng);

    Ok(PrivateKeyImport::new(
        KeyType::EcP384,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[fixture]
fn ecp521_key() -> TestResult<PrivateKeyImport> {
    let private_key = p521::SecretKey::random(&mut rand::rngs::OsRng);

    Ok(PrivateKeyImport::new(
        KeyType::EcP521,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[fixture]
fn rsa_key() -> TestResult<PrivateKeyImport> {
    let private_key =
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, DEFAULT_RSA_BITS.try_into()?)?;

    Ok(PrivateKeyImport::new(
        KeyType::Rsa,
        private_key.to_pkcs8_der()?.as_bytes(),
    )?)
}

#[rstest]
#[ignore = "requires Podman"]
#[tokio::test]
async fn import_keys(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
    ed25519_key: TestResult<PrivateKeyImport>,
    ecp224_key: TestResult<PrivateKeyImport>,
    ecp256_key: TestResult<PrivateKeyImport>,
    ecp384_key: TestResult<PrivateKeyImport>,
    ecp521_key: TestResult<PrivateKeyImport>,
    rsa_key: TestResult<PrivateKeyImport>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let ed25519_key = ed25519_key?;
    let ecp224_key = ecp224_key?;
    let ecp256_key = ecp256_key?;
    let ecp384_key = ecp384_key?;
    let ecp521_key = ecp521_key?;
    let rsa_key = rsa_key?;
    assert_eq!(nethsm.get_keys(None)?.len(), 0);

    nethsm.import_key(
        KeyMechanism::curve25519_mechanisms(),
        ed25519_key,
        None,
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 1);

    nethsm.import_key(
        KeyMechanism::elliptic_curve_mechanisms(),
        ecp224_key,
        None,
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 2);

    nethsm.import_key(
        KeyMechanism::elliptic_curve_mechanisms(),
        ecp256_key,
        None,
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 3);

    nethsm.import_key(
        KeyMechanism::elliptic_curve_mechanisms(),
        ecp384_key,
        None,
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 4);

    nethsm.import_key(
        KeyMechanism::elliptic_curve_mechanisms(),
        ecp521_key,
        None,
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 5);

    nethsm.import_key(KeyMechanism::rsa_mechanisms(), rsa_key, None, None)?;
    assert_eq!(nethsm.get_keys(None)?.len(), 6);

    Ok(())
}
