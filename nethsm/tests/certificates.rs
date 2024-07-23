mod common;
use common::nethsm_with_users;
use common::NetHsmImage;
use common::DEFAULT_KEY_ID;
use common::DEFAULT_OPERATOR_USER_ID;
use common::DEFAULT_RSA_BITS;
use common::DEFAULT_TAG;
use common::ENC_KEY_ID;
use common::OTHER_KEY_ID;
use common::OTHER_OPERATOR_USER_ID;
use common::OTHER_TAG;
use nethsm::{DistinguishedName, KeyMechanism, KeyType, NetHsm, PrivateKeyImport};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
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
        Some(DEFAULT_KEY_ID.to_string()),
        None,
    )?;
    assert!(nethsm.get_keys(None)?.len() == 1);

    println!(
        "Default key on NetHSM: {:?}",
        nethsm.get_key(DEFAULT_KEY_ID)?
    );
    println!(
        "Public key on NetHSM: {}",
        nethsm.get_public_key(DEFAULT_KEY_ID)?
    );

    nethsm.add_key_tag(DEFAULT_KEY_ID, DEFAULT_TAG)?;
    println!(
        "Default key on NetHSM with tag: {:?}",
        nethsm.get_key(DEFAULT_KEY_ID)?
    );

    println!(
        "Certificate Signing Request (CSR) from NetHSM: {}",
        nethsm.get_key_csr(
            DEFAULT_KEY_ID,
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
        Some(OTHER_KEY_ID.to_string()),
        Some(vec![OTHER_TAG.to_string()]),
    )?;
    assert!(nethsm.get_keys(None)?.len() == 2);

    println!(
        "An imported key on the NetHSM: {:?}",
        nethsm.get_key(OTHER_KEY_ID)?
    );
    let other_public_key = nethsm.get_public_key(OTHER_KEY_ID)?;
    println!(
        "The public key of an imported key on the NetHSM: {}",
        other_public_key
    );

    // import a certificate for a key, show it and delete it
    nethsm.import_key_certificate(OTHER_KEY_ID, other_public_key.into_bytes())?;
    println!(
        "An imported key certificate on the NetHSM: {}",
        String::from_utf8(nethsm.get_key_certificate(OTHER_KEY_ID)?)?
    );
    nethsm.delete_key_certificate(OTHER_KEY_ID)?;
    assert!(nethsm.get_key_certificate(OTHER_KEY_ID).is_err());

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
        Some(DEFAULT_RSA_BITS),
        Some(ENC_KEY_ID.to_string()),
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
    nethsm.add_user_tag(DEFAULT_OPERATOR_USER_ID, DEFAULT_TAG)?;
    assert!(nethsm.get_user_tags(DEFAULT_OPERATOR_USER_ID)?.len() == 1);
    nethsm.delete_user_tag(DEFAULT_OPERATOR_USER_ID, DEFAULT_TAG)?;
    assert!(nethsm.get_user_tags(DEFAULT_OPERATOR_USER_ID)?.is_empty());

    nethsm.add_user_tag(OTHER_OPERATOR_USER_ID, OTHER_TAG)?;
    assert!(nethsm.get_user_tags(OTHER_OPERATOR_USER_ID)?.len() == 1);
    nethsm.delete_user_tag(OTHER_OPERATOR_USER_ID, OTHER_TAG)?;
    assert!(nethsm.get_user_tags(OTHER_OPERATOR_USER_ID)?.is_empty());

    nethsm.delete_key_tag(DEFAULT_KEY_ID, DEFAULT_TAG)?;

    nethsm.delete_key(DEFAULT_KEY_ID)?;
    assert!(nethsm.get_keys(None)?.len() == 2);

    Ok(())
}

#[ignore = "requires Podman"]
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
