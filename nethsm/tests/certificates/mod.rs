//! Tests for cryptographic certificates.

use nethsm::test::DEFAULT_AES_BITS;
use nethsm::test::DEFAULT_KEY_ID;
use nethsm::test::DEFAULT_OPERATOR_USER_ID;
use nethsm::test::DEFAULT_RSA_BITS;
use nethsm::test::DEFAULT_TAG;
use nethsm::test::ENC_KEY_ID;
use nethsm::test::NetHsmImage;
use nethsm::test::OTHER_KEY_ID;
use nethsm::test::OTHER_OPERATOR_USER_ID;
use nethsm::test::OTHER_TAG;
use nethsm::test::nethsm_with_users;
use nethsm::{DistinguishedName, KeyMechanism, KeyType, NetHsm, PrivateKeyImport};
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rstest::rstest;
use rustainers::Container;
use testdir::testdir;
use testresult::TestResult;

/// Generate a key and create a CSR with it
async fn generate_signing_key(nethsm: &NetHsm) -> TestResult {
    println!("Generate signing key...");
    assert!(nethsm.get_keys(None)?.is_empty());
    nethsm.generate_key(
        KeyType::Curve25519,
        vec![KeyMechanism::EdDsaSignature],
        None,
        Some(DEFAULT_KEY_ID.parse()?),
        None,
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 1);

    println!(
        "Default key on NetHSM: {:?}",
        nethsm.get_key(&DEFAULT_KEY_ID.parse()?)?
    );
    println!(
        "Public key on NetHSM: {}",
        nethsm.get_public_key(&DEFAULT_KEY_ID.parse()?)?
    );

    nethsm.add_key_tag(&DEFAULT_KEY_ID.parse()?, DEFAULT_TAG)?;
    println!(
        "Default key on NetHSM with tag: {:?}",
        nethsm.get_key(&DEFAULT_KEY_ID.parse()?)?
    );

    println!(
        "Certificate Signing Request (CSR) from NetHSM: {}",
        nethsm.get_key_csr(
            &DEFAULT_KEY_ID.parse()?,
            DistinguishedName {
                country_name: Some("DE".to_string()),
                state_or_province_name: Some("Berlin".to_string()),
                locality_name: Some("Berlin".to_string()),
                organization_name: Some("Foobar Inc".to_string()),
                organizational_unit_name: Some("Department of Foo".to_string()),
                common_name: "Foobar Inc".to_string(),
                email_address: Some("foobar@mcfooface.com".to_string())
            }
        )?
    );
    println!("keys: {:?}", nethsm.get_keys(None)?);

    Ok(())
}

/// Import a pre-generated RSA key
async fn import_key(nethsm: &NetHsm) -> TestResult {
    let private_key = {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, DEFAULT_RSA_BITS.try_into()?)?;
        let file = testdir!().join("rsa_private_key.pem");
        private_key.write_pkcs8_der_file(file.clone())?;
        private_key.to_pkcs8_der()?
    };

    nethsm.import_key(
        vec![KeyMechanism::RsaSignaturePkcs1],
        PrivateKeyImport::new(KeyType::Rsa, private_key.as_bytes())?,
        Some(OTHER_KEY_ID.parse()?),
        Some(vec![OTHER_TAG.to_string()]),
    )?;
    assert_eq!(nethsm.get_keys(None)?.len(), 2);

    println!(
        "An imported key on the NetHSM: {:?}",
        nethsm.get_key(&OTHER_KEY_ID.parse()?)?
    );
    let other_public_key = nethsm.get_public_key(&OTHER_KEY_ID.parse()?)?;
    println!("The public key of an imported key on the NetHSM: {other_public_key}");

    let cert = nethsm.get_key_certificate(&OTHER_KEY_ID.parse()?)?;
    println!("No default key certificate on the NetHSM: {cert:?}",);
    assert!(
        cert.is_none(),
        "Certificate should not be there before import."
    );

    // import a certificate for a key, show it and delete it
    nethsm.import_key_certificate(&OTHER_KEY_ID.parse()?, other_public_key.into_bytes())?;
    let cert = nethsm
        .get_key_certificate(&OTHER_KEY_ID.parse()?)?
        .expect("Certificate to be imported");
    println!(
        "An imported key certificate on the NetHSM: {}",
        String::from_utf8(cert)?
    );
    nethsm.delete_key_certificate(&OTHER_KEY_ID.parse()?)?;
    assert!(
        nethsm
            .get_key_certificate(&OTHER_KEY_ID.parse()?)?
            .is_none()
    );

    Ok(())
}

/// Generate a symmetric encryption key
async fn generate_symmetric_encryption_key(nethsm: &NetHsm) -> TestResult {
    // create a symmetric encryption key
    nethsm.generate_key(
        KeyType::Generic,
        vec![
            KeyMechanism::AesEncryptionCbc,
            KeyMechanism::AesDecryptionCbc,
        ],
        Some(DEFAULT_AES_BITS),
        Some(ENC_KEY_ID.parse()?),
        None,
    )?;

    Ok(())
}

/// Add user tags
async fn user_tags(nethsm: &NetHsm) -> TestResult {
    // NOTE: tags on users need to be created after attaching tags to keys
    println!("Adding user tags...");
    println!("users: {:?}", nethsm.get_users()?);
    println!("keys: {:?}", nethsm.get_keys(None)?);
    nethsm.add_user_tag(&DEFAULT_OPERATOR_USER_ID.parse()?, DEFAULT_TAG)?;
    assert_eq!(
        nethsm
            .get_user_tags(&DEFAULT_OPERATOR_USER_ID.parse()?)?
            .len(),
        1
    );
    nethsm.delete_user_tag(&DEFAULT_OPERATOR_USER_ID.parse()?, DEFAULT_TAG)?;
    assert!(
        nethsm
            .get_user_tags(&DEFAULT_OPERATOR_USER_ID.parse()?)?
            .is_empty()
    );

    nethsm.add_user_tag(&OTHER_OPERATOR_USER_ID.parse()?, OTHER_TAG)?;
    assert_eq!(
        nethsm
            .get_user_tags(&OTHER_OPERATOR_USER_ID.parse()?)?
            .len(),
        1
    );
    nethsm.delete_user_tag(&OTHER_OPERATOR_USER_ID.parse()?, OTHER_TAG)?;
    assert!(
        nethsm
            .get_user_tags(&OTHER_OPERATOR_USER_ID.parse()?)?
            .is_empty()
    );

    nethsm.delete_key_tag(&DEFAULT_KEY_ID.parse()?, DEFAULT_TAG)?;

    nethsm.delete_key(&DEFAULT_KEY_ID.parse()?)?;
    assert_eq!(nethsm.get_keys(None)?.len(), 2);

    Ok(())
}

#[rstest]
#[tokio::test]
async fn certificates(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    generate_signing_key(&nethsm).await?;
    import_key(&nethsm).await?;
    generate_symmetric_encryption_key(&nethsm).await?;
    user_tags(&nethsm).await?;

    Ok(())
}
