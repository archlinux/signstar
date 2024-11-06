use nethsm::Credentials;
use nethsm::Passphrase;
use nethsm::{NetHsm, SignatureType};
use nethsm_tests::nethsm_with_keys;
use nethsm_tests::NetHsmImage;
use nethsm_tests::DEFAULT_KEY_ID;
use nethsm_tests::DEFAULT_OPERATOR_USER_ID;
use nethsm_tests::DEFAULT_OPERATOR_USER_PASSPHRASE;
use nethsm_tests::OTHER_KEY_ID;
use nethsm_tests::OTHER_OPERATOR_USER_ID;
use nethsm_tests::OTHER_OPERATOR_USER_PASSPHRASE;
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
        DEFAULT_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(
            DEFAULT_OPERATOR_USER_PASSPHRASE.to_string(),
        )),
    ));
    nethsm.use_credentials(&DEFAULT_OPERATOR_USER_ID.parse()?)?;

    // create an ed25519 signature
    let signature = nethsm.sign(&DEFAULT_KEY_ID.parse()?, SignatureType::EdDsa, MESSAGE)?;
    println!(
        "A raw signature created using the default key on the NetHSM: {:?}",
        signature
    );

    // verify the ed25519 signature
    let pubkey = nethsm.get_public_key(&DEFAULT_KEY_ID.parse()?)?;
    println!("The default key on the NetHSM: {}", pubkey);
    let pubkey_bytes = ed25519_dalek::pkcs8::PublicKeyBytes::from_public_key_pem(&pubkey)?;
    let pubkey_verifier = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes.to_bytes())?;
    let signature_parsed = ed25519_dalek::Signature::from_slice(&signature)?;
    pubkey_verifier.verify(MESSAGE, &signature_parsed)?;

    // use nethsm as another operator user
    nethsm.add_credentials(Credentials::new(
        OTHER_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string())),
    ));
    nethsm.use_credentials(&OTHER_OPERATOR_USER_ID.parse()?)?;

    // create an RSA PKCS1 signature
    let signature = nethsm.sign(&OTHER_KEY_ID.parse()?, SignatureType::Pkcs1, MESSAGE)?;

    println!(
        "A raw signature created using another key on the NetHSM: {:?}",
        signature
    );

    // verify the RSA PKCS1 signature
    let pubkey = nethsm.get_public_key(&OTHER_KEY_ID.parse()?)?;
    println!("The public key of another key on the NetHSM: {}", pubkey);

    let pubkey = RsaPublicKey::from_public_key_pem(&pubkey)?;
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new_unprefixed(pubkey);
    let signature_parsed = rsa::pkcs1v15::Signature::try_from(signature.as_slice())?;
    println!("A signature created using an RSA pubkey for which the NetHSM provides the private key: {:?}", signature_parsed);
    verifying_key.verify(MESSAGE, &signature_parsed)?;

    Ok(())
}
