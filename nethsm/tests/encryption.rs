// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use common::nethsm_with_keys;
use common::ENC_KEY_ID;
use common::ENC_OPERATOR_USER_ID;
use common::ENC_OPERATOR_USER_PASSPHRASE;
use common::OTHER_KEY_ID;
use common::OTHER_OPERATOR_USER_ID;
use common::OTHER_OPERATOR_USER_PASSPHRASE;
use nethsm::NetHsm;
use nethsm_sdk_rs::models::DecryptMode;
use nethsm_sdk_rs::models::EncryptMode;
use podman_api::api::Container;
use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;
use rstest::rstest;
use testresult::TestResult;

// we have an AES128 encryption key. the message must be a multiple of 32 bytes
// long
pub static MESSAGE: &str = "Hello World! This is a message!!";
// we have an AES128 encryption key. the initialization vector must be a
// multiple of 16 bytes long
pub static IV: &str = "This is unsafe!!";

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn symmetric_encryption_decryption(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container)>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_keys.await?;
    nethsm.add_credentials((
        ENC_OPERATOR_USER_ID.to_string(),
        Some(ENC_OPERATOR_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(ENC_OPERATOR_USER_ID)?;

    println!("NetHSM key information: {:?}", nethsm.get_key(ENC_KEY_ID)?);

    // prepare a raw message
    let message = MESSAGE.as_bytes();
    println!("raw message: {:?}", message);
    let initialization_vector = Some(IV.as_bytes());
    println!("raw initialization vector: {:?}", initialization_vector);

    let encrypted_message = nethsm.encrypt(
        ENC_KEY_ID,
        EncryptMode::AesCbc,
        message,
        initialization_vector,
    )?;

    println!("raw encrypted message: {:?}", encrypted_message);

    let decrypted_message = nethsm.decrypt(
        ENC_KEY_ID,
        DecryptMode::AesCbc,
        &encrypted_message,
        initialization_vector,
    )?;
    println!("raw decrypted message: {:?}", decrypted_message);

    assert_eq!(decrypted_message, MESSAGE.as_bytes());

    container.stop(&Default::default()).await?;
    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn asymmetric_decryption(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container)>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_keys.await?;
    nethsm.add_credentials((
        OTHER_OPERATOR_USER_ID.to_string(),
        Some(OTHER_OPERATOR_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(OTHER_OPERATOR_USER_ID)?;

    let pubkey = RsaPublicKey::from_public_key_pem(&nethsm.get_public_key(OTHER_KEY_ID)?)?;
    let mut rng = rand::thread_rng();
    let encrypted_message = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, MESSAGE.as_bytes())?;
    println!("raw encrypted message: {:?}", encrypted_message);

    let decrypted_message =
        nethsm.decrypt(OTHER_KEY_ID, DecryptMode::Pkcs1, &encrypted_message, None)?;
    println!("raw decrypted message: {:?}", decrypted_message);

    assert_eq!(&decrypted_message, MESSAGE.as_bytes(),);

    container.stop(&Default::default()).await?;
    Ok(())
}
