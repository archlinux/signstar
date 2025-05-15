//! Tests of NetHSM encryption capabilities.

use nethsm::Credentials;
use nethsm::Passphrase;
use nethsm::test::ENC_KEY_ID;
use nethsm::test::ENC_OPERATOR_USER_ID;
use nethsm::test::ENC_OPERATOR_USER_PASSPHRASE;
use nethsm::test::NetHsmImage;
use nethsm::test::OTHER_KEY_ID;
use nethsm::test::OTHER_OPERATOR_USER_ID;
use nethsm::test::OTHER_OPERATOR_USER_PASSPHRASE;
use nethsm::test::nethsm_with_keys;
use nethsm::{DecryptMode, EncryptMode, NetHsm};
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

// we have an AES128 encryption key. the message must be a multiple of 32 bytes
// long
static MESSAGE: &str = "Hello World! This is a message!!";
// we have an AES128 encryption key. the initialization vector must be a
// multiple of 16 bytes long
static IV: &str = "This is unsafe!!";

#[rstest]
#[tokio::test]
async fn symmetric_encryption_decryption(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_keys.await?;
    nethsm.add_credentials(Credentials::new(
        ENC_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(ENC_OPERATOR_USER_PASSPHRASE.to_string())),
    ));
    nethsm.use_credentials(&ENC_OPERATOR_USER_ID.parse()?)?;

    println!(
        "NetHSM key information: {:?}",
        nethsm.get_key(&ENC_KEY_ID.parse()?)?
    );

    // prepare a raw message
    let message = MESSAGE.as_bytes();
    println!("raw message: {message:?}");
    let initialization_vector = Some(IV.as_bytes());
    println!("raw initialization vector: {initialization_vector:?}");

    let encrypted_message = nethsm.encrypt(
        &ENC_KEY_ID.parse()?,
        EncryptMode::AesCbc,
        message,
        initialization_vector,
    )?;

    println!("raw encrypted message: {encrypted_message:?}");

    let decrypted_message = nethsm.decrypt(
        &ENC_KEY_ID.parse()?,
        DecryptMode::AesCbc,
        &encrypted_message,
        initialization_vector,
    )?;
    println!("raw decrypted message: {decrypted_message:?}");

    assert_eq!(decrypted_message, MESSAGE.as_bytes());

    Ok(())
}

#[rstest]
#[tokio::test]
async fn asymmetric_decryption(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_keys.await?;
    nethsm.add_credentials(Credentials::new(
        OTHER_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string())),
    ));
    nethsm.use_credentials(&OTHER_OPERATOR_USER_ID.parse()?)?;

    let pubkey =
        RsaPublicKey::from_public_key_pem(&nethsm.get_public_key(&OTHER_KEY_ID.parse()?)?)?;
    let mut rng = rand::thread_rng();
    let encrypted_message = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, MESSAGE.as_bytes())?;
    println!("raw encrypted message: {encrypted_message:?}");

    let decrypted_message = nethsm.decrypt(
        &OTHER_KEY_ID.parse()?,
        DecryptMode::Pkcs1,
        &encrypted_message,
        None,
    )?;
    println!("raw decrypted message: {decrypted_message:?}");

    assert_eq!(&decrypted_message, MESSAGE.as_bytes(),);

    Ok(())
}
