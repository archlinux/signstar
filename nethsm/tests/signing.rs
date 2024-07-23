mod common;
use common::nethsm_with_keys;
use common::NetHsmImage;
use common::DEFAULT_KEY_ID;
use common::DEFAULT_OPERATOR_USER_ID;
use common::DEFAULT_OPERATOR_USER_PASSPHRASE;
use common::OTHER_KEY_ID;
use common::OTHER_OPERATOR_USER_ID;
use common::OTHER_OPERATOR_USER_PASSPHRASE;
use nethsm::Credentials;
use nethsm::Passphrase;
use nethsm::{NetHsm, SignatureType};
use rsa::pkcs1v15::VerifyingKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use rstest::rstest;
use rustainers::Container;
use sha2::Sha256;
use testresult::TestResult;

pub static MESSAGE: &[u8] = b"Hello World!";

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn signing(
    #[future] nethsm_with_keys: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_keys.await?;
    // use nethsm as operator user
    nethsm.add_credentials(Credentials::new(
        DEFAULT_OPERATOR_USER_ID.to_string(),
        Some(Passphrase::new(
            DEFAULT_OPERATOR_USER_PASSPHRASE.to_string(),
        )),
    ));
    nethsm.use_credentials(DEFAULT_OPERATOR_USER_ID)?;

    // create an ed25519 signature
    let signature = nethsm.sign(DEFAULT_KEY_ID, SignatureType::EdDsa, MESSAGE)?;
    println!(
        "A raw signature created using the default key on the NetHSM: {:?}",
        signature
    );

    // verify the ed25519 signature
    let pubkey = nethsm.get_public_key(DEFAULT_KEY_ID)?;
    println!("The default key on the NetHSM: {}", pubkey);
    let pubkey_verifier = ed25519_compact::PublicKey::from_pem(&pubkey)?;
    let signature_parsed = ed25519_compact::Signature::from_slice(&signature)?;
    pubkey_verifier.verify(MESSAGE, &signature_parsed)?;

    // use nethsm as another operator user
    nethsm.add_credentials(Credentials::new(
        OTHER_OPERATOR_USER_ID.to_string(),
        Some(Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string())),
    ));
    nethsm.use_credentials(OTHER_OPERATOR_USER_ID)?;

    // create an RSA PKCS1 signature
    let signature = nethsm.sign(OTHER_KEY_ID, SignatureType::Pkcs1, MESSAGE)?;

    println!(
        "A raw signature created using another key on the NetHSM: {:?}",
        signature
    );

    // verify the RSA PKCS1 signature
    let pubkey = nethsm.get_public_key(OTHER_KEY_ID)?;
    println!("The public key of another key on the NetHSM: {}", pubkey);

    let pubkey = RsaPublicKey::from_public_key_pem(&pubkey)?;
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new_unprefixed(pubkey);
    let signature_parsed = rsa::pkcs1v15::Signature::try_from(signature.as_slice())?;
    println!("A signature created using an RSA pubkey for which the NetHSM provides the private key: {:?}", signature_parsed);
    verifying_key.verify(MESSAGE, &signature_parsed)?;

    Ok(())
}
