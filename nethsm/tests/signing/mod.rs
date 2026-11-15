//! Tests for cryptographic signatures.

use ed25519_dalek::{
    Signature as Ed25519Signature,
    VerifyingKey as Ed25519VerifyingKey,
    pkcs8::PublicKeyBytes,
};
use nethsm::{
    Credentials,
    NetHsm,
    Passphrase,
    SignatureType,
    test::{
        DEFAULT_KEY_ID,
        DEFAULT_OPERATOR_USER_ID,
        DEFAULT_OPERATOR_USER_PASSPHRASE,
        NetHsmImage,
        OTHER_KEY_ID,
        OTHER_OPERATOR_USER_ID,
        OTHER_OPERATOR_USER_PASSPHRASE,
        nethsm_with_keys,
    },
};
use rsa::{
    PublicKey,
    pkcs1v15::{Signature as Pkcs1v15Signature, VerifyingKey as Pkcs1v15VerifyingKey},
    pkcs8::DecodePublicKey,
    sha2::Sha256,
    signature::Verifier,
};
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

static MESSAGE: &[u8] = b"Hello World!";

#[rstest]
#[tokio::test]
async fn signing(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_keys.await?;
    // use nethsm as operator user
    nethsm.add_credentials(Credentials::new(
        DEFAULT_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(
            DEFAULT_OPERATOR_USER_PASSPHRASE.to_string(),
        )),
    ));
    nethsm.use_credentials(&DEFAULT_OPERATOR_USER_ID.parse()?)?;

    // create an ed25519 signature
    let signature = nethsm.sign(&DEFAULT_KEY_ID.parse()?, SignatureType::EdDsa, MESSAGE)?;
    println!("A raw signature created using the default key on the NetHSM: {signature:?}");

    // verify the ed25519 signature
    let pubkey = nethsm.get_public_key(&DEFAULT_KEY_ID.parse()?)?;
    println!("The default key on the NetHSM: {pubkey}");
    let pubkey_bytes = PublicKeyBytes::from_public_key_pem(&pubkey)?;
    let pubkey_verifier = Ed25519VerifyingKey::from_bytes(&pubkey_bytes.to_bytes())?;
    let signature_parsed = Ed25519Signature::from_slice(&signature)?;
    pubkey_verifier.verify(MESSAGE, &signature_parsed)?;

    // use nethsm as another operator user
    nethsm.add_credentials(Credentials::new(
        OTHER_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string())),
    ));
    nethsm.use_credentials(&OTHER_OPERATOR_USER_ID.parse()?)?;

    // create an RSA PKCS1 signature
    let signature = nethsm.sign(&OTHER_KEY_ID.parse()?, SignatureType::Pkcs1, MESSAGE)?;

    println!("A raw signature created using another key on the NetHSM: {signature:?}");

    // verify the RSA PKCS1 signature
    let pubkey = nethsm.get_public_key(&OTHER_KEY_ID.parse()?)?;
    println!("The public key of another key on the NetHSM: {pubkey}");

    let pubkey = PublicKey::from_public_key_pem(&pubkey)?;
    let verifying_key: Pkcs1v15VerifyingKey<Sha256> = Pkcs1v15VerifyingKey::new_unprefixed(pubkey);
    let signature_parsed = Pkcs1v15Signature::try_from(signature.as_slice())?;
    println!(
        "A signature created using an RSA pubkey for which the NetHSM provides the private key: {signature_parsed:?}"
    );
    verifying_key.verify(MESSAGE, &signature_parsed)?;

    Ok(())
}
